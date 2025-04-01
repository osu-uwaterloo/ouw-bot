import {
    Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ActionRowBuilder, ButtonStyle, PermissionFlagsBits,
    Interaction, GuildMember, GuildMemberRoleManager, Message,
    ButtonInteraction,
    TextChannel,
    MessageCreateOptions,
    InteractionReplyOptions,
    ChatInputCommandInteraction,
    ApplicationCommandOptionType,
    Role,
    Guild,
    ContextMenuCommandBuilder,
    ApplicationCommandType,
    ContextMenuCommandType,
    InteractionContextType,
    UserContextMenuCommandInteraction,
    MessageContextMenuCommandInteraction,
    PermissionsBitField,
    ChannelType,
    Partials,
    SlashCommandBuilder,
    ActivityType,
    DiscordAPIError
} from 'discord.js';
import express, { text } from 'express';
import schedule from 'node-schedule';
import env from './env';
import { encryptUserId, decryptUserId, generateRandomToken } from './encryption';
import getTemplate from './template';
import { sendEmail } from './email';
import * as sheet from './spreadsheet';
import { GoogleSpreadsheetRow } from 'google-spreadsheet';
import Logger from './logging';
import * as utils from './utils';
import { DateTime } from 'luxon';
import speakeasy from 'speakeasy';

type BotInteraction =
    ButtonInteraction |
    ChatInputCommandInteraction |
    MessageContextMenuCommandInteraction |
    UserContextMenuCommandInteraction;

const app: express.Application = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
    ],
    partials: [Partials.Channel],
});

const logger = new Logger(client);

interface verificationInfo {
    timestamp: number,
    interaction: BotInteraction, // The interaction context,
    expiry: number, // The timestamp when the verification link expires
    watiam?: string, // The watiam of the user
    emailSent?: number, // The timestamp when the email was sent, if not sent, it's undefined,
    retries?: number, // Number of retries
    nextRetry?: number, // The verification token in the email
    token?: string // The token for email verification
}

const verificationPool = new Map<string, verificationInfo>();


const checkExpired = () => {
    const now = Date.now();
    for (const [userId, verificationInfo] of verificationPool.entries()) {
        if (!verificationInfo.expiry) continue;
        if (now > verificationInfo.expiry) {
            verificationPool.delete(userId);
        }
    }
}


const PORT = process.env.PORT || 3000;

// Define static routes, ./static/* will be served as /static/*
app.use('/static', express.static('static'));

app.use((req, res, next) => {
    checkExpired();
    next();
});

// Main routes
app.get('/verify/:encryptedUserId', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserId = req.params.encryptedUserId;
    const userId = decryptUserId(encryptedUserId);
    if (!userId) {
        return res.send(getTemplate('error', { message: 'Invalid verification link. It may have expired or corrupted. Try getting a new one from the server.' }));
    }

    try {
        const guild = await client.guilds.fetch(env.SERVER_ID);
        const member = await guild.members.fetch(userId);

        const username = member?.user?.username ?? userId;

        const verificationInfo = verificationPool.get(userId);
        if (!verificationInfo) {
            return res.send(getTemplate('error', { message: 'Verification link does not exist or has expired. Try getting a new one from the server.' }));
        }
        
        res.send(getTemplate('verification', {
            discordId: encryptedUserId,
            discordUsername: username,
            watiam: verificationInfo.watiam ?? '',
            emailSent: !!verificationInfo.emailSent,
            nextRetry: verificationInfo.nextRetry ?? false,
        }));
    } catch (error) {
        console.error('Error during verification:', error);
        res.send(getTemplate('error', { message: 'An error occurred during verification. Please try again.' }));
    }
});

app.post('/send-verification-email', async (req: express.Request, res: express.Response): Promise<any> => {
    const { discordId, watiam } = req.body;
    if (!discordId || !watiam) {
        return res.send({ status: 'error', message: 'Invalid request. Missing parameters.' });
    }
    const userId = decryptUserId(discordId);
    if (!userId) {
        return res.send('Invalid verification link. It may have expired or corrupted. Try getting a new one from the server.');
    }
    if (watiam.length > 8 || !watiam.match(/^[a-z]{1,}\d*[a-z]{1,}$/i)) {
        return res.send({ status: 'error', message: 'Invalid WatIAM ID. Please enter a valid WatIAM ID.' });
    }
    const verificationInfo = verificationPool.get(userId);
    if (!verificationInfo) {
        return res.send({ status: 'error', message: 'Verification link does not exist or has expired. Try getting a new one from the server.' });
    }
    // Check if its before the next retry
    let nextRetry = verificationInfo.nextRetry;
    if (nextRetry && Date.now() < nextRetry) {
        return res.send({ status: 'error', message: `You cannot send email until the next retry. Please wait.` });
    } else if (nextRetry === -1) {
        return res.send({ status: 'error', message: `You have reached the maximum number of retries. Please try again later.` });
    }

    // Generate a random token for verification
    if (!verificationInfo.token) {
        verificationInfo.token = generateRandomToken();
        verificationPool.set(userId, verificationInfo);
    }
    
    // Send email to the user
    const token = verificationInfo.token;
    const link = `${env.URL}/email-verify/click/${discordId}/${token}`;
    const text = `Click the link to verify your email: ${link}. The link will expire in 1 hour. If you did not request this, please DO NOT click the link and ignore this email.`;
    const html = getTemplate('email', { verificationLink: link }); // TODO: Make the email template beautiful
    const to = `${watiam}@uwaterloo.ca`;

    console.log('Sending email to:', to);
    console.log('With verification link:', link);

    try {
        await sendEmail(to, 'Email Verification', text, html);
    } catch (error) {
        console.error('Error sending email:', error);
        return res.send({ status: 'error', message: 'An error occurred while sending the email. Please try again. If the problem persists, please contact the club executives to get verified manually.' });
    }

    // Update the verification pool
    verificationInfo.watiam = watiam;
    verificationInfo.emailSent = Date.now();
    verificationInfo.expiry = Date.now() + 60 * 60 * 1000;

    // Calculate the next retry time
    const retries = verificationInfo.retries ?? 0;
    nextRetry = verificationInfo.emailSent;
    if (nextRetry) {
        if (retries <= 4) {
            nextRetry += [0.5, 1, 2, 3, 5][retries] * 60 * 1000;
        } else {
            nextRetry = -1;
        }
        verificationInfo.nextRetry = nextRetry;
    }
    verificationInfo.retries = retries + 1;
    verificationPool.set(userId, verificationInfo);

    // Logging
    logger.verbose(verificationInfo.interaction.member as GuildMember, 'Sent a verification email', 'They have requested a verification email to verify.', embed => {
        embed.addFields(
            { name: 'WatIAM', value: watiam },
            { name: 'Next Retry', value: nextRetry > 0 ? `<t:${Math.floor(nextRetry / 1000)}:R>` : 'Until the verification link expires' }
        );
    });

    // Send a success response
    res.send({
        status: 'success',
        emailSent: verificationInfo.emailSent,
        nextRetry: nextRetry
    });
});

app.get('/email-verify/click/:encryptedUserId/:token', async (req: express.Request, res: express.Response): Promise<any> => {
    // Redirect in javascript to prevent email client scanning accessing the link
    res.send(getTemplate('email-click', {redirectUrl: `${env.URL}/email-verify/${req.params.encryptedUserId}/${req.params.token}` }));
});

app.get('/email-verify/:encryptedUserId/:token', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserId = req.params.encryptedUserId;
    const token = req.params.token;
    const userId = decryptUserId(encryptedUserId);
    if (!userId) {
        return res.send(getTemplate('error', { message: 'Invalid verification link. It may have expired or corrupted. Try getting a new one from the server.' }));
    }

    const verificationInfo = verificationPool.get(userId);
    if (!verificationInfo) {
        return res.send(getTemplate('error', { message: 'Verification link does not exist or has expired. Try getting a new one from the server.' }));
    }

    if (verificationInfo.token !== token) {
        return res.send(getTemplate('error', { message: 'Invalid verification token.' }));
    }

    const guild = await client.guilds.fetch(env.SERVER_ID);
    const member = await guild.members.fetch(userId);
    if (!member) {
        return res.send(getTemplate('error', { message: 'Cannot find the user in the server. Please join the server first.' }));
    }

    // Remove the user from the verification pool
    verificationPool.delete(userId);

    // Give the verified role to the user
    await member.roles.add(env.ROLE_ID.VERIFIED);
    await member.roles.add(env.ROLE_ID.CURRENT_UW_STUDENT);

    // Send a success message to the user
    //sendExclusiveMessage('You have been successfully verified! Welcome to osu!uwaterloo!', member);
    verificationInfo.interaction.followUp({ content: 'You have been successfully verified! Welcome to osu!uwaterloo!', ephemeral: true });

    // Update the sheet
    try {
        await sheet.addMember(userId, member.user.username, verificationInfo.watiam!);
    } catch (error) {
        console.error('Error adding member to the sheet:', error);
    }

    // Logging
    logger.success(member, 'Has been verified', 'They have completed the email verification process and have been verified as a current UW student.', embed => {
        embed.addFields(
            { name: 'WatIAM', value: verificationInfo.watiam ?? 'Unknown' }
        );
    });

    // Get a membership management link
    const key = `${userId}-${Date.now() + 24 * 60 * 60 * 1000}`;
    const link = `${env.URL}/membership/${encryptUserId(key)}?verified=true`;
    
    res.redirect(link);
});

// restore verification status for rejoining members
async function restoreVerificationStatus(member: GuildMember) {
    const userId = member.id;
    
    const row = await sheet.tryFindRowByMultipleKeyValues([
        ['discord_id', userId],
        ['discord_username', member.user.username]
    ]);
    if (!row) return false;
    if (row.get('watiam')) {
        // give the verified role to the user
        await member.roles.add(env.ROLE_ID.VERIFIED);
        await member.roles.add(env.ROLE_ID.CURRENT_UW_STUDENT);
        
        addMissingFieldsToLegacyRow(member, row);

        return true;
    } else {
        await sheet.deleteRow(row);
        return false;
    }
}

// Listen for new members
client.on('guildMemberAdd', async (member) => {
    if (member.guild.id !== env.SERVER_ID) return;
    if (await restoreVerificationStatus(member)) {
        await sendExclusiveMessage('Welcome back to osu!uwaterloo! Your have been verified.', member);
        logger.success(member, 'Has been verified', 'The user has been verified as a current UW student before. They rejoined the server and have been given the verified role automatically.');
    }
});

// Setup verification button in announcements
async function setupVerificationButtonMessage(message: Message) {
    const embed = new EmbedBuilder()
        .setColor('#feeb1d')
        .setDescription(`
          # Verification
          
          In order to chat in this server, you must be given the <@&${env.ROLE_ID.VERIFIED}> tag.

          ## You are a UWaterloo student

          **If you are a Waterloo student, you can click on the button below to validate yourself as a current student**, which will verify you as well as grant you access to a dedicated section of the server just for actual club members. It also grants you tracking on the ⁠scores-feed, posts your stream to the ⁠stream-hype channel, and gets you added to our club website!

          ## You are not a UWaterloo student

          If you are not a Waterloo student, just let us know how you found your way here and if possible, who invited you, in #manual-verify channel. Ping @Club Executive after doing this and you’ll be given the role ASAP.`
        .replace(/^[ \t\r\f\v]+/gm, '').trim());
        
    const verifyButton = new ButtonBuilder()
        .setCustomId('verify_request')
        .setLabel('Request Verification Link')
        .setStyle(ButtonStyle.Primary);

    const row = new ActionRowBuilder<ButtonBuilder>().addComponents(verifyButton);

    return await (message.channel as TextChannel).send({
        embeds: [embed],
        components: [row]
    });
}

async function onVerifyRequest(interaction: ButtonInteraction) {
    // get all the roles of the user
    const roles = (interaction.member!.roles as GuildMemberRoleManager).cache;
    const isVerified = roles.has(env.ROLE_ID.VERIFIED);
    const isCurrentUWStudent = roles.has(env.ROLE_ID.CURRENT_UW_STUDENT);
    if (isCurrentUWStudent) {
        if (!isVerified) {
            // This circumstance should never happen, but just in case, give them the verified role
            await (interaction.member!.roles as GuildMemberRoleManager).add(env.ROLE_ID.VERIFIED);
            await interaction.reply({
                content: 'You are already a current UW student. I have given you the verified role.',
                ephemeral: true
            });
        } else {
            await interaction.reply({
                content: 'You are already verified as a current UW student.',
                ephemeral: true
            });
        }
        return;
    }
    const hasSkipRole = roles.some(role => env.SKIP_ROLE_IDS.includes(role.id));
    if (hasSkipRole) {
        await interaction.reply({
            content: 'You are already verified as other roles such as Alumni. You do not need to verify again.',
            ephemeral: true
        });
        return;
    }

    // If they are already verified before, give them the role
    if (await restoreVerificationStatus(interaction.member as GuildMember)) {
        await interaction.reply({
            content: 'Welcome back to osu!uwaterloo! Your have been verified.',
            ephemeral: true
        });
        logger.success(interaction.member as GuildMember, 'Has been verified', 'The user has been verified as a current UW student before. They made a verification request and have been given the verified role automatically.');
        return;
    }

    // Generate a verification link and send it to the user
    const member = interaction.member as GuildMember;
    const verificationLink = getVerificationLink(interaction.member as GuildMember);

    verificationPool.set(member.id, {
        timestamp: Date.now(),
        interaction: interaction,
        expiry: Date.now() + 60 * 60 * 1000
    });

    const embed = new EmbedBuilder()
        .setColor('#5865f2')
        .setTitle('Verification Link')
        .setDescription('Click the button below and login with your UWaterloo account to verify');
    
    if (isVerified) {
        embed.addFields({ name: 'Note', value: 'You are already verified, but not as a current UW student. If you are an UW student now, complete the verification process will grant you the current UW student role.' });
    }
    
    const verifyButton = new ButtonBuilder()
        .setURL(verificationLink)
        .setLabel('Verify')
        .setStyle(ButtonStyle.Link);
    
    const row = new ActionRowBuilder<ButtonBuilder>().addComponents(verifyButton);
    

    await interaction.reply({
        embeds: [embed],
        components: [row],
        ephemeral: true
    });
}

function getVerificationLink(member: GuildMember) {
    const encryptedUserId = encryptUserId(member.id);
    return `${env.URL}/verify/${encryptedUserId}`;
}

// Send an exclusive message to the user via DM
// if DM fails, send an ephemeral message in the channel
async function sendExclusiveMessage(message: string | MessageCreateOptions | InteractionReplyOptions, member: GuildMember, interaction: BotInteraction | null = null) {
    try {
        // try DM first
        await member.send(message as (string | MessageCreateOptions));
        return true;
    } catch (error) {
        // if DM fails, send an ephemeral message in the channel
        try {
            if (interaction) {
                if (typeof message === 'string') {
                    message = { content: message };
                }
                await interaction.reply({
                    ...message as InteractionReplyOptions,
                    ephemeral: true
                });
                return true;
            }
        } catch (error) {
            console.error('Error sending exclusive message:', error);
            return false;
        }
    }
    return false;
}

// The sheet has 2 fields: discord_id and discord_username
// We mainly use discord_id to identify the user, but the old entries only have discord_username
// This function will add whatever missing fields to the row
async function addMissingFieldsToLegacyRow(member: GuildMember, row: GoogleSpreadsheetRow | null = null) : Promise<boolean> {
    const userId = member.id;
    const username = member.user.username;
    if (!row) {
        row = await sheet.tryFindRowByMultipleKeyValues([
            ['discord_id', userId],
            ['discord_username', username]
        ]);
    }
    if (!row) return false;
    if (row.get('watiam')) {
        if (row.get('discord_id') !== userId || row.get('discord_username') !== username) {
            await sheet.updateRow(row, {
                discord_id: userId,
                discord_username: username
            });
        }
        return true;
    } else {
        return false;
    }
}

// Manage membership slash command callback
const onSlashCommandManageMembership = async (interaction: ChatInputCommandInteraction) => {
    // Check if the user has the verified role
    const roles = (interaction.member!.roles as GuildMemberRoleManager).cache;
    const isVerified = roles.has(env.ROLE_ID.VERIFIED);
    const isCurrentUWStudent = roles.has(env.ROLE_ID.CURRENT_UW_STUDENT);
    if (!isCurrentUWStudent || !isVerified) {
        await interaction.reply({
            content: 'You need to be a verified current UW student to manage your membership.',
            ephemeral: true
        });
        return;
    }
    // Check if the user has a verified WatIAM in the sheet
    await addMissingFieldsToLegacyRow(interaction.member as GuildMember);
    const userId = (interaction.member as GuildMember).id;
    const row = await sheet.findRowByKeyValue('discord_id', userId);
    if (!row) {
        await interaction.reply({
            content: 'Please contact the club executives to get your data migrated. You have record with outdated discord username.',
            ephemeral: true
        });
        return;
    }
    // Send the user a link to manage their membership
    const expiry = Date.now() + 12 * 60 * 60 * 1000;
    const key = `${userId}-${expiry}`;
    const link = `${env.URL}/membership/${encryptUserId(key)}`;
    const embed = new EmbedBuilder()
        .setColor('#5865f2')
        .setTitle('Manage Membership')
        .setDescription(`Click the button below to manage your membership. This link will expire <t:${Math.floor(expiry / 1000)}:R>.`);
    const manageButton = new ButtonBuilder()
        .setURL(link)
        .setLabel('Manage Membership')
        .setStyle(ButtonStyle.Link);
    const actionRow = new ActionRowBuilder<ButtonBuilder>().addComponents(manageButton);
    await interaction.reply({
        embeds: [embed],
        components: [actionRow],
        ephemeral: true
    });
}


// Membership management routes
const getDataByEncryptedUserIdAndExpiry = async (encryptedUserIdAndExpiry: string | undefined, res: express.Response) => {
    const userIdAndExpiry = decryptUserId(encryptedUserIdAndExpiry);
    if (!userIdAndExpiry) {
        res.send(getTemplate('error', { message: 'Invalid membership management link. It may be corrupted. Please use <code>/manage_membership</code> in the server to get a new link.' }));
        return null;
    }
    const userId = userIdAndExpiry.split('-')[0];
    const expiry = parseInt(userIdAndExpiry.split('-')[1]);

    
    if (!userId) {
        res.send(getTemplate('error', { message: 'Invalid membership management link. It may be corrupted. Please use <code>/manage_membership</code> in the server to get a new link.' }));
        return null;
    }
    if (Date.now() > expiry) {
        res.send(getTemplate('error', { message: 'Membership management link has expired for security reasons. Please use <code>/manage_membership</code> in the server to get a new link.' }));
        return null;
    }

    const row = await sheet.findRowByKeyValue('discord_id', userId);
    if (!row) {
        res.send(getTemplate('error', { message: 'User not found in the database. Please contact the club executives to get your data migrated.' }));
        return null;
    }
    return { userId, expiry, row };
}

// Member social media related types and constants
// TODO: move these to a separate file

// Update social media links
type SocialMediaField = {
    id: string,
    name: string,
    description: string,
    regex: string,
    immutable?: boolean
};
// SocialLink is SocialMediaField with actual value
type SocialLink = SocialMediaField & {
    enabled?: boolean,
    value?: string
};
// Pre-defined social media fields
const socialMediaFields: SocialMediaField[] = [
    {
        id: "discord",
        name: "Discord",
        description: "Username",
        regex: "^[a-zA-Z0-9_]{2,32}$"
    },
    {
        id: "personal-website",
        name: "Personal Website",
        description: "URL (with http(s)://)",
        regex: "^(https?://)?([a-zA-Z0-9]+\\.)?[a-zA-Z0-9][a-zA-Z0-9-]+\\.[a-zA-Z]{2,6}(\\.[a-zA-Z]{2,6})?(/.*)?$"
    },
    {
        id: "github",
        name: "GitHub",
        description: "Username",
        regex: "^[a-zA-Z0-9-]{1,39}$"
    },
    {
        id: "twitch",
        name: "Twitch",
        description: "Username",
        regex: "^[a-zA-Z0-9_]{4,25}$"
    },
    {
        id: "youtube",
        name: "YouTube",
        description: "Channel Handle",
        regex: "^[a-zA-Z0-9_]{1,39}$"
    }
];

// membership management page
app.get('/membership/:encryptedUserIdAndExpiry', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserIdAndExpiry = req.params.encryptedUserIdAndExpiry;
    
    const reqData = await getDataByEncryptedUserIdAndExpiry(encryptedUserIdAndExpiry, res);
    if (!reqData) return;
    const { userId, expiry, row } = reqData;

    // Get the osu account id
    const rawOsu = (row.get('osu') ?? '').trim();
    let osuAccountId = '';
    if (rawOsu.match(/^\d+$/)) {
        osuAccountId = rawOsu;
    } else if (rawOsu.includes('osu.ppy.sh')) {
        osuAccountId = rawOsu.match(/\d+/)[0];
    }

    // Generate social links json
    const socialLinksInSheetJson = (() => {
        const raw = row.get('social_links');
        if (!raw) return {};
        try {
            return JSON.parse(raw);
        } catch (error) {
            return {};
        }
    })();

    const discordUsername = row.get('discord_username') ?? '';

    const socialLinks: SocialLink[] = socialMediaFields.map(field => {
        if (field.id === 'discord' && discordUsername) {
            // If there is a discord username in record, use it and make it immutable
            return {
                ...field,
                enabled: socialLinksInSheetJson['discord'] !== '',
                value: discordUsername,
                immutable: true
            };
        }
        if (socialLinksInSheetJson[field.id]) {
            return {
                ...field,
                enabled: true,
                value: socialLinksInSheetJson[field.id]
            };
        } else {
            return {
                ...field,
                enabled: false
            };
        }
    });
    

    // Send the membership management page
    res.send(getTemplate('membership', {
        token: encryptedUserIdAndExpiry,
        membershipManagementBaseUrl: `${env.URL}/membership/${encryptedUserIdAndExpiry}`,
        discordId: userId,
        discordUsername: row.get('discord_username'),
        watiam: row.get('watiam') ?? 'Unknown',
        osuAccount: osuAccountId,
        displayOnWebsite: utils.parseHumanBool(row.get('display_on_website'), false),
        socialMedia: JSON.stringify(socialLinks)
    }));
});

// link osu account oauth redirect
app.get('/membership/:encryptedUserIdAndExpiry/link-osu-account', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserIdAndExpiry = req.params.encryptedUserIdAndExpiry;
    
    const reqData = await getDataByEncryptedUserIdAndExpiry(encryptedUserIdAndExpiry, res);
    if (!reqData) return;
    const { userId, expiry, row } = reqData;

    // Get the osu account id
    const rawOsu = (row.get('osu') ?? '').trim();
    let osuAccountId = '';
    if (rawOsu.match(/^\d+$/)) {
        osuAccountId = rawOsu;
    } else if (rawOsu.includes('osu.ppy.sh')) {
        osuAccountId = rawOsu.match(/\d+/)[0];
    }

    if (osuAccountId) {
        return res.send(getTemplate('error', { message: 'You have already linked an osu account. If you want to change it, please unlink it in the membership management page first.' }));
    }

    const redirectUri = `${env.URL}/osu-auth-callback`;
    const link = `https://osu.ppy.sh/oauth/authorize?client_id=${env.OSU_CLIENT_ID}&redirect_uri=${redirectUri}&response_type=code&scope=identify&state=${encryptedUserIdAndExpiry}`;
    res.redirect(link);
});

// osu oauth callback
app.get('/osu-auth-callback', async (req: express.Request, res: express.Response): Promise<any> => {
    const { code, state } = req.query;
    const encryptedUserIdAndExpiry = state as string;

    const reqData = await getDataByEncryptedUserIdAndExpiry(encryptedUserIdAndExpiry, res);
    if (!reqData) return;
    const { userId, expiry, row } = reqData;

    const res2 = await fetch('https://osu.ppy.sh/oauth/token', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            client_id: env.OSU_CLIENT_ID,
            client_secret: env.OSU_CLIENT_SECRET,
            code,
            grant_type: 'authorization_code',
            redirect_uri: `${env.URL}/osu-auth-callback`
        })
    });
    const data = await res2.json();
    if (data.error) {
        return res.send(getTemplate('error', { message: `Error linking osu account. Please try again later. Error: ${data.error}` }));
    }

    const accessToken = data.access_token;

    const res3 = await fetch('https://osu.ppy.sh/api/v2/me', {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });
    const userData = await res3.json();
    const osuAccountId = userData.id.toString();

    // Update the row
    await sheet.updateRow(row, {
        osu: `https://osu.ppy.sh/users/${osuAccountId}`
    });

    // Logging
    logger.info(null, 'Linked osu! account', 'They have linked their osu! account.', embed => {
        embed.setAuthor({ name: `@${row.get('discord_username')}`, url: `https://discord.com/users/${userId}` });
        embed.setFooter({ text: `ID: ${userId}` });
        embed.setThumbnail(`https://a.ppy.sh/${osuAccountId}`);
        embed.addFields(
            { name: 'osu! UID', value: osuAccountId, inline: true },
            { name: 'osu! username', value: userData.username, inline: true }
        );
    }, () => {
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setLabel('osu! Profile')
                .setStyle(ButtonStyle.Link)
                .setURL(`https://osu.ppy.sh/users/${osuAccountId}`)
        );
        return row;
    } );

    // Redirect to the membership management page
    res.redirect(`${env.URL}/membership/${encryptedUserIdAndExpiry}`);
});

// unlink osu account
app.post('/membership/:encryptedUserIdAndExpiry/unlink-osu-account', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserIdAndExpiry = req.params.encryptedUserIdAndExpiry;
    
    const reqData = await getDataByEncryptedUserIdAndExpiry(encryptedUserIdAndExpiry, res);
    if (!reqData) return;
    const { userId, expiry, row } = reqData;

    // Get the osu account id
    const rawOsu = (row.get('osu') ?? '').trim();
    let osuAccountId = '';
    if (rawOsu.match(/^\d+$/)) {
        osuAccountId = rawOsu;
    } else if (rawOsu.includes('osu.ppy.sh')) {
        osuAccountId = rawOsu.match(/\d+/)[0];
    }

    if (!osuAccountId) {
        return res.send({ status: 'error', message: 'You have not linked an osu account yet.' });
    }
    
    // Delete the osu account from the row
    await sheet.updateRow(row, {
        osu: ''
    });

    // Logging
    logger.info(null, 'Unlinked osu! account', 'They have unlinked their osu! account.', embed => {
        embed.setAuthor({ name: `@${row.get('discord_username')}`, url: `https://discord.com/users/${userId}` });
        embed.setFooter({ text: `ID: ${userId}` });
        embed.setThumbnail(`https://a.ppy.sh/${osuAccountId}`);
        embed.addFields({ name: 'osu! UID', value: osuAccountId });
    }, () => {
        const row = new ActionRowBuilder().addComponents(
            new ButtonBuilder()
                .setLabel('osu! Profile')
                .setStyle(ButtonStyle.Link)
                .setURL(`https://osu.ppy.sh/users/${osuAccountId}`)
        );
        return row;
    });

    // Return success
    res.send({ status: 'success' });
});

// Update display on website status
app.post('/membership/:encryptedUserIdAndExpiry/update-display-on-website', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserIdAndExpiry = req.params.encryptedUserIdAndExpiry;
    
    const reqData = await getDataByEncryptedUserIdAndExpiry(encryptedUserIdAndExpiry, res);
    if (!reqData) return;
    const { userId, expiry, row } = reqData;

    const displayOnWebsite = req.body.displayOnWebsite;
    await sheet.updateRow(row, {
        display_on_website: displayOnWebsite.toString()
    });

    // Return success
    res.send({ status: 'success' });
});

// Update social media links
app.post('/membership/:encryptedUserIdAndExpiry/update-social-links', async (req: express.Request, res: express.Response): Promise<any> => {
    const encryptedUserIdAndExpiry = req.params.encryptedUserIdAndExpiry;
    
    const reqData = await getDataByEncryptedUserIdAndExpiry(encryptedUserIdAndExpiry, res);
    if (!reqData) return;
    const { userId, expiry, row } = reqData;

    const socialLinks = req.body.socialLinks;

    
    const discordUsernameInSheet = row.get('discord_username') ?? '';

    // Validate
    for (const key in socialLinks) {
        const field = socialMediaFields.find(field => field.id === key);
        const value = socialLinks[key];
        if (!field) {
            return res.send({ status: 'error', message: `Invalid social media field: ${key}` });
        }
        if (typeof value !== 'string') {
            return res.send({ status: 'error', message: `Invalid value for ${field.name}` });
        }
        if (key === 'discord' && discordUsernameInSheet) {
            // If they have a discord username in record, special check for discord later
            continue;
        }
        if (!value.match(new RegExp(field.regex))) {
            return res.send({ status: 'error', message: `Invalid value for ${field.name}` });
        }
    }
    // Validate discord username
    if ('discord' in socialLinks && discordUsernameInSheet) {
        const value = socialLinks['discord'];
        if (value !== discordUsernameInSheet && value !== '') {
            return res.send({ status: 'error', message: 'Invalid value for Discord username.' });
        }
        if (value === discordUsernameInSheet) {
            delete socialLinks['discord'];
        }
    }

    // Update the row
    await sheet.updateRow(row, {
        social_links: JSON.stringify(socialLinks)
    });

    // Return success
    res.send({ status: 'success' });
});


// Server custom colour roles self-assign
const getServerColourRoles = async (guild: Guild): Promise<{
    range: [number, number] | null, // (startPosition, endPosition), exclusive
    colourRoles: Role[]
}> => {
    let allServerRoles = await guild.roles.fetch();
    allServerRoles = allServerRoles.sort((a, b) => b.position - a.position);
    const array = Array.from(allServerRoles.values());
    let startIndex = -1, endIndex = -1;
    let startPosition = -1, endPosition = -1;
    for (let i = 0; i < array.length; i++) {
        const role = array[i];
        if (role.id === env.COLOUR_ROLE_IDS.COLOUR_ROLE_SECTION_BEGIN) {
            startIndex = i;
            startPosition = role.position;
            if (endIndex !== -1) break;
        } else if (role.id === env.COLOUR_ROLE_IDS.COLOUR_ROLE_SECTION_END) {
            endIndex = i;
            endPosition = role.position;
            if (startIndex !== -1) break;
        }
    }
    // notice higher roles also have higher positions
    if (startIndex === -1 || endIndex === -1) {
        return { range: null, colourRoles: [] };
    }
    if (startIndex > endIndex) {
        [startIndex, endIndex] = [endIndex, startIndex];
        [startPosition, endPosition] = [endPosition, startPosition];
    }
    return {
        range: [startPosition, endPosition],
        colourRoles: array.slice(startIndex + 1, endIndex)
    };
}

async function onSlashCommandSetNameColour(interaction: ChatInputCommandInteraction) {
    // If the user is not verified, reject
    const member = interaction.member as GuildMember;
    const roles = member.roles.cache.sort((a, b) => b.position - a.position);
    const isVerified = roles.has(env.ROLE_ID.VERIFIED);
    if (!isVerified) {
        await interaction.reply({
            content: 'You need to be verified to set a custom name colour.',
            ephemeral: true
        });
        return;
    }

    // Parse the hex colour
    const hex = utils.parseHexColour(interaction.options.getString('hex', true));
    if (!hex) {
        await interaction.reply({
            content: 'Please enter a valid hex colour code. Example: `#ff66ab`.',
            ephemeral: true
        });
        return;
    }

    // Check if it is #000000
    if (hex === '#000000') {
        await interaction.reply({
            content: 'Discord does not allow setting the name colour to black, as it represents the default colour (no colour) of the role. Please choose a different colour.',
            ephemeral: true
        });
        return;
    }

    // Check colour contrast
    const contrastDark = utils.calculateColourContrast(hex, '#313338');
    const contrastLight = utils.calculateColourContrast(hex, '#ffffff');
    if (contrastDark < 2 || contrastLight < 1.25) {
        await interaction.reply({
            content: `
                The colour you have chosen does not have enough contrast with the background. Please choose a colour with better contrast.

                WCAG Contrast Ratio:
                **Dark Theme:** ${contrastDark.toFixed(2)} ${contrastDark >= 2 ? '✅' : '❌'} (>= 2 Required)
                **Light Theme:** ${contrastLight.toFixed(2)} ${contrastLight >= 1.25 ? '✅' : '❌'} (>= 1.25 Required)

                You can use [this tool](https://webaim.org/resources/contrastchecker/?fcolor=${contrastDark < 2 ? '313338' : 'ffffff'}&bcolor=${hex.slice(1)}) to check the contrast.

                If you really want to use this colour, please contact an executive.
            `.replace(/^[ \t\r\f\v]+/gm, '').trim(),
            ephemeral: true
        });
        return;
    }

    // Get server colour roles
    const guild = interaction.guild!;
    const {
        range: serverColourRoleRange,
        colourRoles: serverColourRoles
    } = await getServerColourRoles(guild);
    if (!serverColourRoleRange) {
        await interaction.reply({
            content: 'Server colour roles are not set up properly. Please contact the server administrators.',
            ephemeral: true
        });
        return;
    }
    const [startPosition, endPosition] = serverColourRoleRange;

    // Get member's top coloured role
    let topColourRole = null;
    for (const role of roles.values()) {
        if (role.color !== 0) {
            topColourRole = role;
            break;
        }
    }

    // If top colour role is higher than the server colour roles, reject
    if (topColourRole && topColourRole.position > startPosition) {
        await interaction.reply({
            content: 'You already have coloured role(s) that has higher priority than the server colour roles. Please contact an executive if you want to set a custom colour.',
            ephemeral: true
        });
        return;
    }

    // If their colour role is in the server colour roles and has >= 2 people using it, remove it first
    if (
        topColourRole &&
        topColourRole.position < startPosition && topColourRole.position > endPosition &&
        topColourRole.members.size > 1
    ) {
        await member.roles.remove(topColourRole);
        topColourRole = null;
    }

    // If their colour role is in the server colour roles and has 1 person using it, update it
    if (
        topColourRole &&
        topColourRole.position < startPosition && topColourRole.position > endPosition &&
        topColourRole.members.size === 1
    ) {
        const isHexName = topColourRole.name.match(/^#?[0-9a-fA-F]{6}$/);
        if (isHexName) {
            await topColourRole.edit({ name: hex, color: hex });
        } else {
            await topColourRole.edit({ color: hex });
        }
        await interaction.reply({
            content: `Your name colour has been set to \`${hex}\`.`,
            ephemeral: true
        });
        logger.info(member, 'Set custom name colour', `Set their name colour to ${hex}.\nColour role: <@&${topColourRole.id}>`);
        return;
    }

    // If they dont have a top colour role, or their top colour role is lower than the server colour roles
    // try assigning an existing colour role, or create a new one
    const availableRole = serverColourRoles.find(role => role.name.toLowerCase() === hex);
    if (availableRole) {
        await member.roles.add(availableRole);
        await interaction.reply({
            content: `Your name colour has been set to \`${hex}\`.`,
            ephemeral: true
        });
        logger.info(member, 'Set custom name colour', `Set their name colour to ${hex}.\nColour role: <@&${availableRole.id}>`);
        return;
    } else {
        const newRole = await guild.roles.create({
            name: hex,
            color: hex,
            position: endPosition + 1,
            reason: 'User requested a custom name colour through the bot'
        });
        await member.roles.add(newRole);
        await interaction.reply({
            content: `Your name colour has been set to \`${hex}\`.`,
            ephemeral: true
        });
        logger.info(member, 'Set custom name colour', `Set their name colour to ${hex}.\nColour role: <@&${newRole.id}>`);
        return;
    }
}

const onSlashCommandRemoveNameColour = async (interaction: ChatInputCommandInteraction) => {
    // If the user is not verified, reject
    const member = interaction.member as GuildMember;
    const roles = member.roles.cache.sort((a, b) => b.position - a.position);
    const isVerified = roles.has(env.ROLE_ID.VERIFIED);
    if (!isVerified) {
        await interaction.reply({
            content: 'You need to be verified to remove your custom name colour.',
            ephemeral: true
        });
        return;
    }

    // Get server colour roles
    const guild = interaction.guild!;
    const {
        range: serverColourRoleRange,
    } = await getServerColourRoles(guild);
    if (!serverColourRoleRange) {
        await interaction.reply({
            content: 'Server colour roles are not set up properly. Please contact the server administrators.',
            ephemeral: true
        });
        return;
    }
    const [startPosition, endPosition] = serverColourRoleRange;

    // Get member's top coloured role
    let topColourRole = null;
    for (const role of roles.values()) {
        if (role.color !== 0) {
            topColourRole = role;
            break;
        }
    }

    // If their colour role is within the range of server colour roles, remove it
    if (topColourRole && topColourRole.position < startPosition && topColourRole.position > endPosition) {
        // If there is only 1 person using the role, delete it
        if (topColourRole.members.size === 1) {
            await topColourRole.delete();
        } else {
            await member.roles.remove(topColourRole);
        }
        await interaction.reply({
            content: 'Your custom name colour has been reverted to the default.',
            ephemeral: true
        });
        logger.info(member, 'Remove custom name colour', 'Removed their custom name colour.');
    } else {
        await interaction.reply({
            content: 'You do not have a custom name colour to remove. If you want to set one, use `/name_colour set`.',
            ephemeral: true
        });
        return;
    }
}

async function setupColourRolesMessage(message: Message) {
    const embed = new EmbedBuilder()
        .setColor('#ff66ab')
        .setDescription(`
            # Name Colours
            
            You can customize your name colour by using the following commands in any channel:
            ## \`/name_colour set [hex]\`
            to set your name colour to a custom hex colour code.
            ## \`/name_colour remove\`
            to revert your name colour to the default.
        `.replace(/^[ \t\r\f\v]+/gm, '').trim());

    return await (message.channel as TextChannel).send({
        embeds: [embed],
    });
}

// Manual verification shortcut
async function manualAddVerifiedRoles(
    interaction: BotInteraction,
    roleIds: string[],
    member: GuildMember,
    invoker: GuildMember,
    originalMessage: Message | null = null
) {
    roleIds = roleIds.filter(roleId => !member.roles.cache.has(roleId));
    if (roleIds.length === 0) {
        await interaction.reply({
            content: 'The user already has the role(s) you are trying to give.',
            ephemeral: true
        });
        return;
    }
    for (const roleId of roleIds) {
        await member.roles.add(roleId);
    }
    logger.success(member, 'Role given', `Role <@&${roleIds.join('>, <@&')}> has been given to <@${member.id}>`, embed => {
        embed.addFields({ name: 'Given by', value: `<@${invoker.id}>` });
    });
    if (originalMessage) {
        const row = new ActionRowBuilder<ButtonBuilder>().addComponents(
            new ButtonBuilder()
                .setLabel('React ✅ to original message')
                .setStyle(ButtonStyle.Primary)
                .setCustomId(`react_tick_to_message_${originalMessage.id}`)
        );
        await interaction.reply({
            content: `Role <@&${roleIds.join('>, <@&')}> has been given to <@${member.id}>.`,
            ephemeral: true,
            components: [row]
        });
    } else {
        await interaction.reply({
            content: `Role <@&${roleIds.join('>, <@&')}> has been given to <@${member.id}>.`,
            ephemeral: true
        });
    }
}
const reactTickToMessage = async (interaction: ButtonInteraction) => {
    const originalMessageId = interaction.customId.split('_').pop();
    if (!originalMessageId) {
        await interaction.reply({
            content: 'Invalid button ID.',
            ephemeral: true
        });
        return;
    }
    const originalMessage = await interaction.channel!.messages.fetch(originalMessageId);
    await originalMessage.react('✅');
    await interaction.update({
        components: []
    });
}

// New non-UW student verification by inviter
client.on('messageCreate', async (message) => {
    if (message.channelId !== env.VERIFY_CHANNEL_ID) {
        return;
    }
    if (message.author.bot) {
        return;
    }
    if (message.member!.roles.cache.has(env.ROLE_ID.VERIFIED)) {
        return;
    }
    const mentions = message.mentions.members;
    if (!mentions || mentions.size > 2) {
        return;
    }
    const inviters = mentions.filter(member => {
        if (member.roles.cache.has(env.ROLE_ID.CURRENT_UW_STUDENT)) return true;
        for (const skipRole of env.SKIP_ROLE_IDS) {
            if (member.roles.cache.has(skipRole)) return true;
        }
        return false;
    });
    if (!inviters.size) {
        return;
    }

    message.reply({
        content: `
            Hi! Welcome to osu UWaterloo!

            ${inviters.map(inviter => `<@${inviter.id}>`).join(' ')}, can you confirm that you know this person?

            If you do, please click the button below, and they will be automatically verified. If you don't know them, please click the other button.

            -# The buttons are only for ${inviters.map(inviter => `<@${inviter.id}>`).join(', ')} and <@&${env.EXEC_ROLE_ID}>.
        `.replace(/^[ \t\r\f\v]+/gm, '').trim(),
        components: [
            new ActionRowBuilder<ButtonBuilder>().addComponents(
                new ButtonBuilder()
                    .setLabel('Yes, I know them')
                    .setStyle(ButtonStyle.Success)
                    .setCustomId(`verify_invention_request_from_${message.author.id}_yes_${inviters.map(inviter => inviter.id).join('_')}`),
                new ButtonBuilder()
                    .setLabel('No, I don\'t know them')
                    .setStyle(ButtonStyle.Danger)
                    .setCustomId(`verify_invention_request_from_${message.author.id}_no_${inviters.map(inviter => inviter.id).join('_')}`),
            )
        ]
    });

    // Log the message
    logger.info(message.member!, 'Created a invitation verification request', `The user sent a verification request to the mentioned members. [Message Link](${message.url})`, embed => {
        embed.addFields(
            { name: 'Inviters given by the user', value: inviters.map(inviter => `<@${inviter.id}>`).join(', ') },
            { name: 'Message', value: message.content }
        );
    });
});

async function onVerifyInventionRequest(interaction: ButtonInteraction) {
    const {inviteeId, yesNo, inviterIdsStr} = interaction.customId.match(/^verify_invention_request_from_(?<inviteeId>\d+)_(?<yesNo>yes|no)_(?<inviterIdsStr>.+)$/)?.groups ?? {};
    if (!inviteeId || !yesNo ) {
        await interaction.reply({
            content: 'Invalid button ID.',
            ephemeral: true
        });
        return;
    }
    const isYes = (yesNo === 'yes');
    const inviterIds = inviterIdsStr.split('_');
    
    const botMessage = interaction.message as Message;
    
    const isMod = (interaction.member!.permissions as Readonly<PermissionsBitField>).has(PermissionFlagsBits.ManageRoles);
    const isInviter = inviterIds.includes(interaction.user.id);

    if (!isMod && !isInviter) {
        await interaction.reply({
            content: 'This button is not for you. 🥺',
            ephemeral: true
        });
        return;
    }

    const invitee = await interaction.guild!.members.fetch(inviteeId);
    if (!invitee) {
        await interaction.reply({
            content: 'User not found. They may have left the server.',
            ephemeral: true
        });
        await botMessage.edit({ components: [] });
        return;
    }
    if (invitee.roles.cache.has(env.ROLE_ID.VERIFIED)) {
        await interaction.reply({
            content: 'The user is already verified.',
            ephemeral: true
        });
        await botMessage.edit({ components: [] });
        return;
    }
    
    const isPreviouslyEdited = !!botMessage.editedAt;

    if (isMod) {
        if (isYes) {
            logger.success(invitee, 'Invitation verification request accepted by a mod', `A moderator has verified this user\'s invitation verification request. They have been given the verified role. [Message Link](${botMessage.url})`, embed => {
                embed.addFields({ name: 'Accepted by', value: `<@${interaction.user.id}>` });
            });
            Promise.all([
                invitee.roles.add(env.ROLE_ID.VERIFIED),
                botMessage.edit({
                    content: botMessage.content + (isPreviouslyEdited ? '\n' : '\n\n') + '> ✅ A moderator has verified this user.'
                }),
                botMessage.edit({ components: [] })
            ]);
        } else {
            logger.error(invitee, 'Invitation verification request denied by a mod', `A moderator has denied this user\'s invitation verification request. [Message Link](${botMessage.url})`, embed => {
                embed.addFields({ name: 'Denied by', value: `<@${interaction.user.id}>` });
            });
            Promise.all([
                botMessage.edit({
                    content: botMessage.content + (isPreviouslyEdited ? '\n' : '\n\n') + '> ❌ A moderator has denied this verification request.',
                    components: []
                }),
                botMessage.edit({ components: [] })
            ]);
        }
    } else {
        if (isYes) {
            logger.success(invitee, 'Invitation verification request accepted by a member', `The inviter has confirmed that they know this user. They have been given the verified role. [Message Link](${botMessage.url})`, embed => {
                embed.addFields({ name: 'Confirmed by', value: `<@${interaction.user.id}>` });
            });
            Promise.all([
                invitee.roles.add(env.ROLE_ID.VERIFIED),
                botMessage.edit({
                    content: botMessage.content + (isPreviouslyEdited ? '\n' : '\n\n') + `> ✅ <@${interaction.user.id}> has confirmed that they know this user. The user has been given the verified role.`
                }),
                botMessage.edit({ components: [] })
            ]);
        } else {
            await botMessage.edit({
                content: botMessage.content + (isPreviouslyEdited ? '\n' : '\n\n') + `> ❌ <@${interaction.user.id}> has confirmed that they do not know this user.`,
                components: []
            });
            const newInviterIds = inviterIds.filter(id => id !== interaction.user.id);
            if (newInviterIds.length === 0) {
                await botMessage.edit({ components: [] });
            } else {
                await botMessage.edit({ components: [
                    new ActionRowBuilder<ButtonBuilder>().addComponents(
                        new ButtonBuilder()
                            .setLabel('Yes, I know them')
                            .setStyle(ButtonStyle.Success)
                            .setCustomId(`verify_invention_request_from_${inviteeId}_yes_${newInviterIds.join('_')}`),
                        new ButtonBuilder()
                            .setLabel('No, I don\'t know them')
                            .setStyle(ButtonStyle.Danger)
                            .setCustomId(`verify_invention_request_from_${inviteeId}_no_${newInviterIds.join('_')}`),
                    )
                ] });
                await interaction.deferUpdate();
            }
        }
    }
}

// Club Twitch account related 
async function setupTwitch2FAMessage(message: Message) {
    const embed = new EmbedBuilder()
        .setColor('#9146ff')
        .setTitle('Get 2FA Code for Club Twitch Account')
        .setDescription(`
            Click the button below to get the 2FA code for the club Twitch account.

            Contact @solstice23 if you have any issues.
        `.replace(/^[ \t\r\f\v]+/gm, '').trim());

    
    const button = new ButtonBuilder()
        .setCustomId('get_twitch_2fa_code')
        .setLabel('Get 2FA Code')
        .setStyle(ButtonStyle.Primary);

    const actionRow = new ActionRowBuilder<ButtonBuilder>().addComponents(button);

    return await (message.channel as TextChannel).send({
        embeds: [embed],
        components: [actionRow],
    });
}

async function onGetTwitch2FACode(interaction: ButtonInteraction) {
	const totpUrl = env.TWITCH_2FA_TOTP_URL;

    const secret = totpUrl.startsWith('otpauth://totp/') ? totpUrl.match(/secret=([A-Z2-7]+)/)?.[1] : null;
    
	if (!secret) {
        await interaction.reply({
            content: 'Error: Bot is not configured properly. The Twitch 2FA secret is missing. Please contact the bot developer.',
            ephemeral: true
        });
        return;
	}

	const token = speakeasy.totp({
        secret: secret,
        encoding: 'base32'
	});

    await interaction.reply({
        content: `# Twitch 2FA Code: \`${token}\`\n\n-# This code will expire in 30 seconds. If the code doesn't work, click the button again.`,
        ephemeral: true
    });
}

// export reaction members watiams
async function exportReactionMembers(interaction: BotInteraction, message: Message) {
    // defer interaction
    await interaction.deferReply({ ephemeral: true });

    // refresh cache
    await message.fetch();
    await Promise.all(message.reactions.cache.map(reaction => reaction.users.fetch()));

    const reactions: { emoji: string | null; members: string[]; watiams?: string[] }[] = message.reactions.cache.map(reaction => {
        return {
            emoji: reaction.emoji.id ? `\`:${reaction.emoji.name}:\`` : reaction.emoji.name,
            members: reaction.users.cache.map(user => user.id)
        };
    });
    
    // lookup watiams
    const rows = await sheet.getAllRows();

    reactions.forEach(reaction => {
        reaction.watiams = reaction.members.map(memberId => {
            const row = rows.find(row => row.get('discord_id') === memberId);
            return row ? row.get('watiam') : null;
        }).filter(watiam => !!watiam);
    });

    // reply
    await interaction.followUp({
        content: `Here is a list of watiams of reacted members:\n-# Members without watiams in database will not be listed.\n` +
                reactions.map(reaction => {
                    return `## Reaction: ${reaction.emoji}\n\`\`\`\n${reaction.watiams?.join('\n')}\`\`\``
                }).join('\n'),
        ephemeral: true
    });
}

// view member info
async function viewMemberInfo(interaction: BotInteraction, member: GuildMember) {
    const userId = member.id;
    const row = await sheet.findRowByKeyValue('discord_id', userId);

    const embed = new EmbedBuilder()
        .setTitle("User Info")
        .setColor("#bbbbbb");
    
    if (row) {
        for (let [key, value] of Object.entries(row.toObject())) {
            if (!value) value = 'N/A';
            embed.addFields({ name: key, value: value });
        }
    } else {
        embed.setDescription('Cannot find the user in the database.');
    }

    embed.setAuthor({ name: member.user.tag, iconURL: member.user.displayAvatarURL(), url: `https://discord.com/users/${member.id}` });
    embed.setFooter({ text: `ID: ${userId}` });
    embed.setThumbnail(member.user.displayAvatarURL());

    await interaction.reply({
        embeds: [embed],
        ephemeral: true
    });
}

// Slash commands and context menu
// Register slash command and context menu
client.once('ready', async () => {
    const guild = await client.guilds.fetch(env.SERVER_ID);
    await Promise.all([
        guild.commands.create({
            name: 'manage_membership',
            description: 'Manage my membership (osu! account connection, listing on website, etc.)'
        }),
        guild.commands.create({
            name: 'name_colour',
            description: 'Manage your name colour',
            options: [
                {
                    name: 'set',
                    description: 'Set your name colour as a custom hex colour code',
                    type: ApplicationCommandOptionType.Subcommand,
                    options: [
                        {
                            name: 'hex',
                            description: 'The hex colour code',
                            type: ApplicationCommandOptionType.String,
                            required: true,
                            max_length: 7,
                            min_length: 3
                        }
                    ]
                },
                {
                    name: 'remove',
                    description: 'Remove your custom name colour, reverting to the default',
                    type: ApplicationCommandOptionType.Subcommand
                }
            ]
        }),
        // For user context menu
        guild.commands.create(
            new ContextMenuCommandBuilder()
                .setName('give_verified_role')
                .setNameLocalization('en-US', 'Give Verified Role')
                .setType(ApplicationCommandType.User as ContextMenuCommandType)
                .setContexts(InteractionContextType.Guild)
                .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
        ),
        guild.commands.create(
            new ContextMenuCommandBuilder()
                .setName('give_verified_uw_student_role')
                .setNameLocalization('en-US', 'Give Verified & UW Student Role')
                .setType(ApplicationCommandType.User as ContextMenuCommandType)
                .setContexts(InteractionContextType.Guild)
                .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
        ),
        guild.commands.create(
            new ContextMenuCommandBuilder()
                .setName('view_member_info')
                .setNameLocalization('en-US', 'View Member Info')
                .setType(ApplicationCommandType.User as ContextMenuCommandType)
                .setContexts(InteractionContextType.Guild)
                .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
        ),
        // For message context menu
        guild.commands.create(
            new ContextMenuCommandBuilder()
                .setName('give_verified_role')
                .setNameLocalization('en-US', 'Give Verified Role')
                .setType(ApplicationCommandType.Message as ContextMenuCommandType)
                .setContexts(InteractionContextType.Guild)
                .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
        ),
        guild.commands.create(
            new ContextMenuCommandBuilder()
                .setName('give_verified_uw_student_role')
                .setNameLocalization('en-US', 'Give Verified & UW Student Role')
                .setType(ApplicationCommandType.Message as ContextMenuCommandType)
                .setContexts(InteractionContextType.Guild)
                .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
        ),
        guild.commands.create(
            new ContextMenuCommandBuilder()
                .setName('export_reaction_members')
                .setNameLocalization('en-US', 'Export Reaction Members')
                .setType(ApplicationCommandType.Message as ContextMenuCommandType)
                .setContexts(InteractionContextType.Guild)
                .setDefaultMemberPermissions(PermissionFlagsBits.ManageRoles)
        ),
    ]);
});

        
// Handle slash commands
client.on('interactionCreate', async (interaction) => {
    if (interaction.guildId !== env.SERVER_ID) return;
    if (!interaction.isCommand()) return;

    const { commandName } = interaction;

    if (commandName === 'manage_membership') {
        await onSlashCommandManageMembership(interaction as ChatInputCommandInteraction);
    } else if (commandName === 'name_colour') {
        const subcommand = (interaction as ChatInputCommandInteraction).options.getSubcommand();
        if (subcommand === 'set') {
            await onSlashCommandSetNameColour(interaction as ChatInputCommandInteraction);
        } else if (subcommand === 'remove') {
            await onSlashCommandRemoveNameColour(interaction as ChatInputCommandInteraction);
        }
    }
});

// Handle context menu
// Handle both user and message context menu commands
client.on('interactionCreate', async (interaction) => {
    if (interaction.guildId !== env.SERVER_ID) return;
    if (!interaction.isContextMenuCommand()) return;
    if (!interaction.guild) return;
    const isUserContextMenuCommand = interaction.isUserContextMenuCommand();
    const isMessageContextMenuCommand = interaction.isMessageContextMenuCommand();

    const { commandName } = interaction;
    const targetMassage = isMessageContextMenuCommand ? interaction.targetMessage : null;
    const targetMember = isUserContextMenuCommand ?
                        (interaction as UserContextMenuCommandInteraction).targetMember:
                        targetMassage?.member ?? (
                            targetMassage?.author.id ?
                            await interaction.guild.members.fetch(targetMassage.author.id)
                            : null
                        );

    if (!targetMember) {
        await interaction.reply({
            content: 'Cannot find the target user. They may have left the server.',
            ephemeral: true
        });
        return;
    }
    if (targetMember.user.bot) {
        await interaction.reply({
            content: 'Cannot give roles to bots.',
            ephemeral: true
        });
        return;
    }
    const member = interaction.member as GuildMember;

    if (commandName === 'give_verified_role' || commandName === 'give_verified_uw_student_role') {
        const roleIds = [env.ROLE_ID.VERIFIED];
        if (commandName === 'give_verified_uw_student_role') {
            roleIds.push(env.ROLE_ID.CURRENT_UW_STUDENT);
        }
        await manualAddVerifiedRoles(interaction as BotInteraction, roleIds, targetMember as GuildMember, member, targetMassage);
    }
});
// Handle message context menu
client.on('interactionCreate', async (interaction) => {
    if (interaction.guildId !== env.SERVER_ID) return;
    if (!interaction.isContextMenuCommand()) return;
    if (!interaction.guild) return;
    if (!interaction.isMessageContextMenuCommand()) return;

    const { commandName } = interaction;
    const targetMessage = interaction.targetMessage;
    

    if (commandName === 'export_reaction_members') {
        await exportReactionMembers(interaction as BotInteraction, targetMessage);
    }
});
// Handle user context menu
client.on('interactionCreate', async (interaction) => {
    if (interaction.guildId !== env.SERVER_ID) return;
    if (!interaction.isContextMenuCommand()) return;
    if (!interaction.guild) return;
    if (!interaction.isUserContextMenuCommand()) return;

    const { commandName } = interaction;
    const targetMember = interaction.targetMember;

    if (commandName === 'view_member_info') {
        await viewMemberInfo(interaction as BotInteraction, targetMember as GuildMember);
    }
});


// Command to setup the special messages with admin permissions
client.on('messageCreate', async (message) => {
    if (message.guildId !== env.SERVER_ID) return;
    if (!message.member) return;
    if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
        return;
    }
    if (message.content === '!setupverify') {
        await setupVerificationButtonMessage(message);
        await message.delete();
    } else if (message.content === '!setupcolourroles') {
        await setupColourRolesMessage(message);
        await message.delete();
    } else if (message.content === '!setuptwitch2fa') {
        await setupTwitch2FAMessage(message);
        await message.delete();
    }
});

// Handle button interactions
client.on('interactionCreate', async (interaction: Interaction) => {
    if (interaction.guildId !== env.SERVER_ID) return;
    if (!interaction.isButton()) return;

    const action = interaction.customId;

    if (action === 'verify_request') {
        await onVerifyRequest(interaction as ButtonInteraction);
    } else if (action.startsWith('react_tick_to_message_')) {
        await reactTickToMessage(interaction as ButtonInteraction);
    } else if (action.startsWith('verify_invention_request_from_')) {
        await onVerifyInventionRequest(interaction as ButtonInteraction);
    } else if (action === 'get_twitch_2fa_code') {
        await onGetTwitch2FACode(interaction as ButtonInteraction);
    }
});

// Leave other guilds
client.on('guildCreate', async (guild) => {
    if (guild.id !== env.SERVER_ID) {
        await guild.leave();
    }
});

// Send "Time" when its 7:27 PM in toronto time in the time channel
if (env.TIME_727_SPAM_CHANNEL_ID) {
    const rule = new schedule.RecurrenceRule();
    rule.hour = 19;
    rule.minute = 27;
    rule.tz = 'America/Toronto';

    schedule.scheduleJob(rule, async () => {
        const channel = await client.channels.fetch(env.TIME_727_SPAM_CHANNEL_ID) as TextChannel;
        if (!channel) return;
        await channel.send('time');
    });
}

// Easter egg: react "+- minutes" (e.g +3) to time messages within 7:27 PM +- 10 minutes
client.on('messageCreate', async (message) => {
    if (message.guildId !== env.SERVER_ID) return;
    if (!message.member) return;
    if (message.author.bot) return;
    if (!message.content) return;
    if (
        message.content.replace(/\W/g, '').match(/^time[time]*$/i) ||
        utils.deHomoglyph(message.content).replace(/\W/g, '').match(/^time[time]*$/i) ||
        utils.equalToObfuscatedStrings(message.content, ['time'])
    ) {
        const messageTime = DateTime.fromJSDate(message.createdAt).setZone('America/Toronto');
        const [h, m] = [messageTime.hour, messageTime.minute];
        if (h === 19 && m === 27) return; // do nothing at actual time
        if (h === 7 && m === 27) { // rare AM time
            Promise.all([
                message.react('‼️'),
                message.reply('Rare AM Time!!')
            ]);
            return;
        }
        if (h === 19 && m >= 27 - 10 && m <= 27 + 10) { // time +- 10 minutes
            const sign = Math.sign(m - 27) === 1 ? '➕' : '➖';
            const diff = Math.abs(m - 27);
            await message.react(sign);
            const emojis = ['0️⃣', '1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣', '🔟'];
            await message.react(emojis[diff]);
            try {
                // if (m > 27) {
                //     await message.member.send(`Skill issue, you missed the time by ${diff} minutes. Nice try, appreciate the effort!`);
                // } else {
                //     await message.author.send(`It\'s almost the time but not quite yet! Could you please wait ${diff} minute${diff > 1 ? 's' : ''} patiently? 🥺`);
                // }
            } catch (e) {}
            return;
        }
        // else
        try {
            // await message.react('❓'),
            // await message.member.send('It\'s not the time yet!!! skill issue')
        } catch (e: any) {
            // if (e.code === 90001) {
            //     await message.reply('It\'s not the time yet!!! skill issue\nand pls don\'t block me 🥺 🥺');
            // }
        }
    }
    
});

// Fun: follow up on consecutive repeated messages
let channelLatestMessages: {[channelId: string]: {text: string, bySelf: boolean, time: Date}[]} = {};
client.on('messageCreate', async (message) => {
    if (message.guildId !== env.SERVER_ID) return;
    if (!message.member) return;
    if (!message.content) return;
    if (message.author.bot) return; // we don't count bot messages, even if it's the bot itself. we add the message sent by bot to the list separately later
    const bySelf = message.author.id === client.user?.id;
    const channelId = message.channelId;
    const content = message.content.trim().toLowerCase();
    if (content.match(/^[!>][a-z]+/)) return; // ignore bot commands
    if (!channelLatestMessages[channelId]) channelLatestMessages[channelId] = [];
    channelLatestMessages[channelId].push({ text: content, bySelf, time: message.createdAt });
    while (
        channelLatestMessages[channelId].length > 150 ||
        (channelLatestMessages[channelId].length > 1 && new Date().getTime() - channelLatestMessages[channelId][0].time.getTime() > 1000 * 60 * 60 * 12)
    ) {
        channelLatestMessages[channelId].shift();
    }
    let consecutiveLength = 0;
    for (let i = channelLatestMessages[channelId].length - 1; i >= 0 && channelLatestMessages[channelId][i].text === content; i--) {
        consecutiveLength++;
    }
    if (consecutiveLength < 3) return;

    // check if the bot already followed up
    // consecutive non-content 10 messages will break the streak
    // count all messages in the streak, if there is a message that is sent by the bot, do not follow up
    let streakBreakCounter = 0;
    for (let i = channelLatestMessages[channelId].length - 1; i >= 0; i--) {
        if (channelLatestMessages[channelId][i].text === content) {
            streakBreakCounter = 0;
            if (channelLatestMessages[channelId][i].bySelf) {
                // if the bot already followed up, do not follow up again
                return;
            }
        } else {
            streakBreakCounter++;
            if (streakBreakCounter >= 10) {
                break;
            }
        }
    }

    // follow up
    channelLatestMessages[channelId].push({ text: content, bySelf: true, time: new Date() });
    setTimeout(() => message.channel.send({
        content: message.content.trim()
    }), 1500);
});

// Easter egg: react cat to meowssages
client.on('messageCreate', async (message) => {
    if (message.guildId !== env.SERVER_ID) return;
    if (!message.member) return;
    if (message.content && !message.author.bot) {
        const meows = message.content.split(/\W+/).filter(word => word.match(/^(m+[er]*o+w+[meow]*|mew[mew*]|n+([ya]{4,}|y+)a+|pu+rr+|mrr+p)+/i));
        if (meows.length > message.content.split(/\W+/).length * 0.2 || meows.reduce((acc, val) => acc + val.length, 0) > message.content.length * 0.25) {
            if (meows.length > 0) {
                await message.react('🐱');
            }
            if (meows.length > 4 || meows.reduce((acc, val) => acc + val.length, 0) > 15) {
                await message.reply('meow mew mew mew nya nayayyaayya mrewo nya purrrrrrrrrr mrew :3');
            }
        }
    }

    if (message.content && !message.author.bot) {
        if (message.content.toLowerCase().match(/https:\/\/tenor\.com\/view\/(.*?)(nailong|yellow(.*?)dragon|dino)/g)) {
            message.react('🚫');
            const hasDuplicatedChar = (str: string) => str.length !== new Set(str).size;
            const noDuplicateRandom = (min: number, max: number) => {
                let random;
                while (true) {
                    random = Math.floor(Math.random() * (max - min + 1)) + min;
                    if (!hasDuplicatedChar(random.toString())) {
                        break;
                    }
                }
                return random;
            }
            const time = noDuplicateRandom(15, 130);
            const emojis = ['0️⃣', '1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣'];
            try {
                await message?.member?.timeout(time * 1000, "Posting nailong");
                for (const digit of time.toString()) {
                    await message.react(emojis[parseInt(digit)]);
                }
                await message.react('🇸');
            } catch (e) {}
        }
    }
});

// Direct message forwarding
client.on('messageCreate', async (message) => {
    if (message.channel.type !== ChannelType.DM) return;
    if (!(env?.ADMIN_IDS ?? []).includes(message.author.id)) return;
    const content = (message.content ?? '').trim();
    if (!content) return;
    let command: "message" | "react" | null = null;
    if (content.startsWith("!sendmsg") || content.startsWith("!msg") || content.startsWith("!message") || content.startsWith("!send")) {
        command = "message";
    } else if (content.startsWith("!react")) {
        command = "react";
    } else {
        return;
    }
    const splited = content.split(' ').slice(1);
    if (splited.length < 2) return;
    const target = splited[0];
    let sendContent = splited.slice(1).join(' ');
    
    let targetChannelId: string | null = null, targetMessageId: string | null = null;
    let targetChannel: TextChannel | null = null, targetMessage: Message | null = null;

    if (target.match(/^\d{15,}$/)) {
        targetChannelId = target;
    } else if (target.match(/^https:\/\/discord.com\/channels\/(\d+)\/(\d+)\/(\d+)\/?$/)) {
        const [_, guildId, channelId, messageId] = target.match(/^https:\/\/discord.com\/channels\/(\d+)\/(\d+)\/(\d+)$/) ?? [];
        if (guildId !== env.SERVER_ID) return;
        targetChannelId = channelId;
        targetMessageId = messageId;
    } else if (target.match(/^https:\/\/discord.com\/channels\/(\d+)\/(\d+)\/?$/)) {
        const [_, guildId, channelId] = target.match(/^https:\/\/discord.com\/channels\/(\d+)\/(\d+)$/) ?? [];
        if (guildId !== env.SERVER_ID) return;
        targetChannelId = channelId;        
    }
    if (!targetChannelId) return;
    targetChannel = await client.channels.fetch(targetChannelId) as TextChannel;
    if (!targetChannel) return;
    if (targetMessageId) {
        targetMessage = await targetChannel.messages.fetch(targetMessageId);
        if (!targetMessage) {
            message.reply('Target message not found.');
            return;
        }
    }
    if (command === "message") {
        // parse mentions
        const guild = targetChannel.guild;
        if (sendContent.includes('@')) {
            await guild.members.fetch();
        }
        sendContent = sendContent.replace(/@([a-z0-9\._]{2,32})/gi, (match) => {
            const username = match.slice(1);
            const member = guild.members.cache.find(member => member.user.username === username);
            if (member) {
                return `<@${member.id}>`;
            }
            return match;
        });
        try {
            let linkOfSentMessage = '';
            if (targetMessage) {
                linkOfSentMessage = (await targetMessage.reply(sendContent)).url;
            } else {
                linkOfSentMessage = (await targetChannel.send(sendContent)).url;
            }
            if (linkOfSentMessage) {
                message.reply(`Sent: ${linkOfSentMessage}`);
            }
        } catch (e) {}
    } else if (command === "react") {
        if (!targetMessage) return;
        const emojis = sendContent.split(' ');
        for (const emoji of emojis) {
            try {
                await targetMessage.react(emoji);
            } catch (e) {}
        }
        message.reply(`Reacted ${targetMessage.url}`);
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Verification server running on port ${PORT}`);
});

client.login(env.DISCORD_BOT_TOKEN);

client.once('ready', () => {
    // client.user?.setPresence({ activities: [] });
    client.user?.setActivity('Photon Pulse', { type: ActivityType.Listening });


    // April Fools day
    (async () => {
        const getName = (user: GuildMember) => {
            return {
                discordName: user.user.displayName,
                nickname: user.nickname ?? ''
            }
        }
        let channelLatestMessages: {[channelId: string]: {userId: string}[]} = {};

        let originalNames: {[userId: string]: {
            discordName: string;
            nickname: string;
        }} = {};

        try {
            originalNames = JSON.parse(await sheet.kvGet('april_fools_original_names_backup') ?? '{}');
            console.log("loaded original names backup", originalNames);
        } catch (e) {
            console.log("cannot read original names backup, assuming empty", e);
            originalNames = {};
        }

        const backupOriginalNames = async () => {
            try {
                await sheet.kvSet('april_fools_original_names_backup', JSON.stringify(originalNames));
            } catch (e) {
                console.error(e);
            }
        }
        const hasOriginalNameRecorded = (userId: string) => {
            return originalNames[userId] !== undefined;
        }
        const recordOriginalName = (user: GuildMember) => {
            if (hasOriginalNameRecorded(user.id)) return;
            originalNames[user.id] = getName(user);
            backupOriginalNames();
        }
        const getOriginalName = (userId: string) => {
            const nickname = originalNames[userId]?.nickname;
            const discordName = originalNames[userId]?.discordName;
            if (nickname !== '') {
                return nickname;
            } else {
                return discordName;
            }
        }
        const setNickname = async (user: GuildMember, nickname: string) => {
            try {
                await user.setNickname(nickname, 'April Fools Day');
                console.log("successfully set nickname", nickname);
            } catch (e) {
                if ((e as DiscordAPIError).code === 50013) return;
                console.error(e);
                logger.error(user, '[April fools] Failed to set nickname', `Failed to set nickname for user ${user.user.tag}. ` + (e as Error)?.message);
            }
        }

        client.on('messageCreate', async (message) => {
            if (message.guildId !== env.SERVER_ID) return;
            if (!message.member) return;
            if (message.author.bot) return;
            if (message.webhookId) return;
            if (message.content === '!restoreaprilfoolsname') return;

            
            const messageTime = DateTime.fromJSDate(message.createdAt).setZone('America/Toronto');
            const [month, day] = [messageTime.month, messageTime.day];
            if (month !== 4 || day !== 1) return;


            const channelId = message.channelId;
            const user = message.member as GuildMember;
            if (!channelLatestMessages[channelId]) channelLatestMessages[channelId] = [];
            let msgQueue = channelLatestMessages[channelId];

            if (!msgQueue.length) {
                // fetch if the queue is empty
                try {
                    const msgs = await message.channel.messages.fetch({ limit: 25 });
                    channelLatestMessages[channelId] = msgs
                        .filter(msg => !msg.webhookId && !msg.author.bot && message.member)
                        .reverse()
                        .map(msg => {
                            return { userId: msg.author.id };
                        });
                    msgQueue = channelLatestMessages[channelId];
                    console.log("fetched messages", msgQueue);
                    msgs.forEach(msg => {
                        const user = msg.member as GuildMember;
                        if (!user) return;
                        recordOriginalName(user);
                    });
                } catch (e) {
                    console.error(e);
                }
            }

            if (msgQueue.length && msgQueue[msgQueue.length - 1].userId === message.author.id) {
                // if the same user sent twice, ignore the second time
                return;
            }

            // record
            recordOriginalName(user);

            // update nickname
            if (msgQueue.length > 0) {
                const lastUser = msgQueue[msgQueue.length - 1].userId;
                const lastUserName = getOriginalName(lastUser);
                console.log("set nickname", lastUserName);
                setNickname(user, lastUserName);
            }

            // update the queue
            msgQueue.push({ userId: message.author.id });
            while (msgQueue.length > 200) {
                msgQueue.shift();
            }
        });



        client.on('messageCreate', async (message) => {
            if (message.guildId !== env.SERVER_ID) return;
            if (!message.member) return;
            if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
                return;
            }
            if (message.content !== '!restoreaprilfoolsname') return;

            message.channel.send('Restoring original names...');

            
            for (const userId in originalNames) {
                const user = await message.guild!.members.fetch(userId).catch(() => null);
                if (!user) continue;

                let nickname:string | null = originalNames[userId]?.nickname ?? '';

                if (nickname === '') nickname = null;
                
                user.setNickname(nickname, '[April fools] Restoring original name').catch(e => {
                    message.reply(`Failed to set nickname for user ${user.user.tag}. ` + (e as Error)?.message);
                });
            }

            message.channel.send('Done restoring original names!');
        });
    })();

});
