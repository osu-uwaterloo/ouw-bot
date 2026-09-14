export type PublicMemberCategory = 'executive' | 'member' | 'alumni';

export interface PublicMember {
    category: PublicMemberCategory;
    username: string | null;
    userId: number | null;
    discord?: string | null;
    website?: string | null;
    twitch?: string | null;
    youtube?: string | null;
    github?: string | null;
    name?: string | null;
    bio?: string | null;
    role?: string | null;
}

export interface PublicMemberSnapshot {
    version: 1;
    generatedAt: string;
    members: PublicMember[];
}

export interface MemberRow {
    get(key: string): unknown;
}

export interface DiscordMemberProfile {
    username: string;
    roleIds: ReadonlySet<string>;
}

export interface PublicMemberRoleConfig {
    executiveRoleId: string;
    executiveTitles?: ReadonlyArray<{
        roleId: string;
        title: string;
    }>;
    alumniRoleId: string;
    currentStudentRoleId: string;
}

interface CachedOsuUsername {
    username: string;
    expiresAt: number;
}

let osuAccessToken: { value: string; expiresAt: number } | null = null;
const osuUsernameCache = new Map<number, CachedOsuUsername>();
const OSU_USERNAME_CACHE_MS = 6 * 60 * 60 * 1_000;

function text(value: unknown): string {
    return typeof value === 'string' ? value.trim() : '';
}

function parseSocialLinks(value: unknown): Record<string, string> {
    if (typeof value !== 'string' || value.length === 0) return {};
    try {
        const parsed = JSON.parse(value);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
        return Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string, string] => {
            return typeof entry[1] === 'string';
        }));
    } catch {
        return {};
    }
}

function parseOsuUserId(value: unknown): number | null {
    const raw = text(value);
    const match = raw.match(/^\d+$/) ?? raw.match(/osu\.ppy\.sh\/users\/(\d+)/i);
    const parsed = Number(match?.[1] ?? match?.[0]);
    return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function normalizeWebsite(value: string | undefined): string | null {
    const trimmed = value?.trim();
    if (!trimmed) return null;
    return /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
}

function getCategory(
    roleIds: ReadonlySet<string>,
    config: PublicMemberRoleConfig,
): PublicMemberCategory | null {
    if (roleIds.has(config.executiveRoleId) || config.executiveTitles?.some(({ roleId }) => roleIds.has(roleId))) {
        return 'executive';
    }
    if (roleIds.has(config.alumniRoleId)) return 'alumni';
    if (roleIds.has(config.currentStudentRoleId)) return 'member';
    return null;
}

function getExecutiveTitle(
    roleIds: ReadonlySet<string>,
    config: PublicMemberRoleConfig,
): string {
    return config.executiveTitles?.find(({ roleId }) => roleIds.has(roleId))?.title ?? 'Executive';
}

export function buildPublicMemberSnapshot(
    rows: MemberRow[],
    discordMembers: ReadonlyMap<string, DiscordMemberProfile>,
    config: PublicMemberRoleConfig,
    generatedAt = new Date(),
): PublicMemberSnapshot {
    const members: PublicMember[] = [];

    for (const row of rows) {
        const discordId = text(row.get('discord_id'));
        const discordMember = discordMembers.get(discordId);
        if (!discordMember) continue;

        const category = getCategory(discordMember.roleIds, config);
        if (!category) continue;
        const displayOnWebsite = ['true', 'yes', '1', 'on'].includes(text(row.get('display_on_website')).toLowerCase());
        if (category !== 'executive' && !displayOnWebsite) continue;

        const socialLinks = parseSocialLinks(row.get('social_links'));
        const discord = socialLinks.discord === ''
            ? null
            : discordMember.username || text(row.get('discord_username')) || null;
        const userId = parseOsuUserId(row.get('osu'));
        if (!userId && !discord) continue;

        members.push({
            category,
            username: null,
            userId,
            discord,
            website: normalizeWebsite(socialLinks['personal-website']),
            twitch: text(socialLinks.twitch) || null,
            youtube: text(socialLinks.youtube) || null,
            github: text(socialLinks.github) || null,
            name: text(socialLinks.name).slice(0, 20) || null,
            bio: text(socialLinks.bio).slice(0, 200) || null,
            role: category === 'executive' ? getExecutiveTitle(discordMember.roleIds, config) : null,
        });
    }

    return {
        version: 1,
        generatedAt: generatedAt.toISOString(),
        members,
    };
}

async function getOsuAccessToken(clientId: string, clientSecret: string): Promise<string> {
    const now = Date.now();
    if (osuAccessToken && osuAccessToken.expiresAt > now + 60_000) return osuAccessToken.value;

    const response = await fetch('https://osu.ppy.sh/oauth/token', {
        method: 'POST',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            client_id: clientId,
            client_secret: clientSecret,
            grant_type: 'client_credentials',
            scope: 'public',
        }),
        signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error(`osu! token request returned ${response.status}`);

    const data = await response.json() as { access_token?: string; expires_in?: number };
    if (!data.access_token) throw new Error('osu! token response did not include an access token');
    osuAccessToken = {
        value: data.access_token,
        expiresAt: now + Math.max(60, data.expires_in ?? 3_600) * 1_000,
    };
    return data.access_token;
}

async function refreshOsuUsernames(
    userIds: number[],
    clientId: string,
    clientSecret: string,
): Promise<void> {
    const now = Date.now();
    if (userIds.length === 0) return;

    const accessToken = await getOsuAccessToken(clientId, clientSecret);
    for (let offset = 0; offset < userIds.length; offset += 50) {
        const ids = userIds.slice(offset, offset + 50);
        const url = new URL('https://osu.ppy.sh/api/v2/users');
        for (const id of ids) url.searchParams.append('ids[]', id.toString());

        const response = await fetch(url, {
            headers: {
                'Accept': 'application/json',
                'Authorization': `Bearer ${accessToken}`,
            },
            signal: AbortSignal.timeout(10_000),
        });
        if (!response.ok) throw new Error(`osu! users request returned ${response.status}`);

        const data = await response.json() as { users?: { id?: number; username?: string }[] };
        for (const user of data.users ?? []) {
            if (!Number.isSafeInteger(user.id) || !user.username) continue;
            osuUsernameCache.set(user.id!, {
                username: user.username,
                expiresAt: now + OSU_USERNAME_CACHE_MS,
            });
        }
    }
}

export async function getOsuUsername(
    userId: number,
    clientId: string,
    clientSecret: string,
    forceRefresh = false,
): Promise<string | null> {
    const cached = osuUsernameCache.get(userId);
    if (forceRefresh || !cached || cached.expiresAt <= Date.now()) {
        await refreshOsuUsernames([userId], clientId, clientSecret);
    }
    return osuUsernameCache.get(userId)?.username ?? null;
}

export async function enrichOsuUsernames(
    snapshot: PublicMemberSnapshot,
    clientId: string,
    clientSecret: string,
): Promise<PublicMemberSnapshot> {
    const now = Date.now();
    const userIds = Array.from(new Set(snapshot.members.flatMap(member => member.userId ? [member.userId] : [])));
    const missingIds = userIds.filter(userId => (osuUsernameCache.get(userId)?.expiresAt ?? 0) <= now);

    if (missingIds.length > 0) {
        await refreshOsuUsernames(missingIds, clientId, clientSecret);
    }

    return {
        ...snapshot,
        members: snapshot.members.map(member => ({
            ...member,
            username: member.userId
                ? osuUsernameCache.get(member.userId)?.username ?? member.username
                : member.username,
        })),
    };
}

export async function pushPublicMemberSnapshot(
    endpoint: string,
    token: string,
    snapshot: PublicMemberSnapshot,
): Promise<void> {
    const response = await fetch(endpoint, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(snapshot),
        signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
        const responseBody = (await response.text()).slice(0, 500);
        throw new Error(`members API returned ${response.status}: ${responseBody}`);
    }
}
