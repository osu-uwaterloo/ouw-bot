import {
    Client, GatewayIntentBits, EmbedBuilder, ButtonBuilder, ActionRowBuilder, ButtonStyle, PermissionFlagsBits,
    Interaction, GuildMember, GuildMemberRoleManager, Message,
    ButtonInteraction,
    TextChannel,
    MessageCreateOptions,
    InteractionReplyOptions,
    ChatInputCommandInteraction
} from 'discord.js';
import express from 'express';
import env from './env.js';
import { encryptUserId, decryptUserId, generateRandomToken } from './encryption';
import getTemplate from './template';
import { sendEmail } from './email';
import * as sheet from './spreadsheet';
import { GoogleSpreadsheetRow } from 'google-spreadsheet';
import Logger from './logging';
import * as utils from './utils';

type BotInteraction = ButtonInteraction | ChatInputCommandInteraction;

const app: express.Application = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent
    ]
});

const logger = new Logger(client);

interface verificationInfo {
    timestamp: number,
    interaction: Interaction, // The interaction context,
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


const PORT = 3000;

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
    console.log(req.body);
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
    const link = `${env.URL}/email-verify/${discordId}/${token}`;
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

    // Give the verified role to the user
    await member.roles.add(env.ROLE_ID.VERIFIED);
    await member.roles.add(env.ROLE_ID.CURRENT_UW_STUDENT);

    // Send a success message to the user
    sendExclusiveMessage('You have been successfully verified! Welcome to osu!uwaterloo.', member);

    // Update the sheet
    try {
        await sheet.addMember(userId, member.user.username, verificationInfo.watiam!);
    } catch (error) {
        console.error('Error adding member to the sheet:', error);
    }
    
    // Remove the user from the verification pool
    verificationPool.delete(userId);

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
    if (await restoreVerificationStatus(member)) {
        await sendExclusiveMessage('Welcome back to osu!uwaterloo! Your have been verified.', member);
        logger.success(member, 'Has been verified', 'The user has been verified as a current UW student before. They rejoined the server and have been given the verified role automatically.');
    }
});

// Setup verification button in announcements
async function setupVerificationButton(message: Message) {
    const embed = new EmbedBuilder()
        .setColor('#feeb1d')
        .setDescription(`
          # Verification
          
          In order to chat in this server, you must be given the @Verified tag.

          ## You are a UWaterloo student

          **If you are a Waterloo student, you can click on the button below to validate yourself as a current student**, which will verify you as well as grant you access to a dedicated section of the server just for actual club members. It also grants you tracking on the ⁠scores-feed, posts your stream to the ⁠stream-hype channel, and gets you added to our club website!

          ## You are not a UWaterloo student

          If you are not a Waterloo student, just let us know how you found your way here and if possible, who invited you, in #manual-verify channel. Ping @Club Executive after doing this and you’ll be given the role ASAP.`
        .replace(/^\s+/gm, '').trim());
        
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

// Handle button interactions
client.on('interactionCreate', async (interaction: Interaction) => {
    if (!interaction.isButton()) return;

    const action = interaction.customId;
    
    switch (action) {
        case 'verify_request':
            await onVerifyRequest(interaction);
            break;
    }
});


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

// Command to setup the verification button in announcements
client.on('messageCreate', async (message) => {
    if (message.content === '!setupverify' && 
        message.member!.permissions.has(PermissionFlagsBits.Administrator)) {
        await setupVerificationButton(message);
    }
});

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

// Slash command to manage membership
client.on('interactionCreate', async (interaction) => {
    if (!interaction.isCommand()) return;

    const { commandName } = interaction;

    if (commandName === 'manage_membership') {
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
        const expiry = Date.now() + 24 * 60 * 60 * 1000;
        const key = `${userId}-${expiry}`;
        const link = `${env.URL}/membership/${encryptUserId(key)}`;
        const embed = new EmbedBuilder()
            .setColor('#5865f2')
            .setTitle('Manage Membership')
            .setDescription(`Click the button below to manage your membership`);
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
});

// Register slash command
client.once('ready', async () => {
    const guild = await client.guilds.fetch(env.SERVER_ID);
    await guild.commands.create({
        name: 'manage_membership',
        description: 'Manage my membership (osu! account connection, listing on website, etc.)'
    });
});


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

    // Send the membership management page
    res.send(getTemplate('membership', {
        token: encryptedUserIdAndExpiry,
        membershipManagementBaseUrl: `${env.URL}/membership/${encryptedUserIdAndExpiry}`,
        discordId: userId,
        discordUsername: row.get('discord_username'),
        watiam: row.get('watiam') ?? 'Unknown',
        osuAccount: osuAccountId,
        displayOnWebsite: utils.parseHumanBool(row.get('display_on_website'), false)
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

// Start the server
app.listen(PORT, () => {
    console.log(`Verification server running on port ${PORT}`);
});

client.login(env.DISCORD_BOT_TOKEN);