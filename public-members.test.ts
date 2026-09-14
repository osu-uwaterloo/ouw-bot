import assert from 'node:assert/strict';
import test from 'node:test';
import { buildPublicMemberSnapshot, enrichOsuUsernames, type MemberRow } from './public-members.js';

const roles = {
    executiveRoleId: 'exec',
    alumniRoleId: 'alumni',
    currentStudentRoleId: 'student',
};

function row(values: Record<string, unknown>): MemberRow {
    return { get: key => values[key] };
}

test('builds the three website sections from Discord roles with executive precedence', () => {
    const rows = [
        row({ discord_id: '1', display_on_website: 'TRUE', osu: 'https://osu.ppy.sh/users/10' }),
        row({ discord_id: '2', display_on_website: 'yes', osu: '20' }),
        row({ discord_id: '3', display_on_website: '1', osu: '30' }),
    ];
    const discordMembers = new Map([
        ['1', { username: 'one', roleIds: new Set(['student', 'exec', 'alumni']) }],
        ['2', { username: 'two', roleIds: new Set(['student']) }],
        ['3', { username: 'three', roleIds: new Set(['alumni']) }],
    ]);

    const snapshot = buildPublicMemberSnapshot(rows, discordMembers, roles, new Date('2026-09-13T12:00:00Z'));

    assert.deepEqual(snapshot.members.map(member => member.category), ['executive', 'member', 'alumni']);
    assert.equal(snapshot.members[0].userId, 10);
    assert.equal(snapshot.members[0].role, 'Executive');
});

test('honours website opt-in and hidden Discord while normalizing website links', () => {
    const rows = [
        row({ discord_id: '1', display_on_website: 'false', osu: '10' }),
        row({
            discord_id: '2',
            display_on_website: 'true',
            osu: '20',
            social_links: JSON.stringify({
                discord: '',
                'personal-website': 'example.com/about',
                github: 'example',
                bio: 'Mapper, player, and tournament enjoyer.',
            }),
        }),
    ];
    const discordMembers = new Map([
        ['1', { username: 'private', roleIds: new Set(['student']) }],
        ['2', { username: 'hidden', roleIds: new Set(['student']) }],
    ]);

    const snapshot = buildPublicMemberSnapshot(rows, discordMembers, roles);

    assert.equal(snapshot.members.length, 1);
    assert.equal(snapshot.members[0].discord, null);
    assert.equal(snapshot.members[0].website, 'https://example.com/about');
    assert.equal(snapshot.members[0].github, 'example');
    assert.equal(snapshot.members[0].bio, 'Mapper, player, and tournament enjoyer.');
});

test('does not publish opted-in rows without a current section role', () => {
    const snapshot = buildPublicMemberSnapshot(
        [row({ discord_id: '1', display_on_website: 'true', osu: '10' })],
        new Map([['1', { username: 'one', roleIds: new Set(['verified']) }]]),
        roles,
    );

    assert.deepEqual(snapshot.members, []);
});

test('fills osu usernames from the batched osu API', async t => {
    const originalFetch = globalThis.fetch;
    t.after(() => { globalThis.fetch = originalFetch; });
    globalThis.fetch = async input => {
        const url = input.toString();
        if (url.endsWith('/oauth/token')) {
            return Response.json({ access_token: 'token', expires_in: 3600 });
        }
        assert.match(url, /ids%5B%5D=42/);
        return Response.json({ users: [{ id: 42, username: 'osu-name' }] });
    };

    const snapshot = buildPublicMemberSnapshot(
        [row({ discord_id: '1', display_on_website: 'true', osu: '42' })],
        new Map([['1', { username: 'discord-name', roleIds: new Set(['student']) }]]),
        roles,
    );
    const enriched = await enrichOsuUsernames(snapshot, 'client', 'secret');

    assert.equal(enriched.members[0].username, 'osu-name');
});
