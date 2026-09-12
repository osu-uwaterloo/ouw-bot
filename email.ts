import nodemailer, { Transporter } from 'nodemailer';
import env from './env.js';

// Exchange Online is retiring Basic auth for SMTP client submission, and the club
// mailbox is already refused with "535 5.7.139 ... did not meet the criteria".
// Three transports are supported, picked by whichever credentials are configured:
//   1. Cloudflare Email Service  (CF_EMAIL_API_TOKEN)
//   2. Microsoft OAuth2          (SMTP_OAUTH_* client credentials)
//   3. Legacy user/password      (SMTP_PASSWORD)
const mode: 'cloudflare' | 'oauth' | 'password' =
    env.CF_EMAIL_API_TOKEN ? 'cloudflare' :
    (env.SMTP_OAUTH_TENANT_ID && env.SMTP_OAUTH_CLIENT_ID && env.SMTP_OAUTH_CLIENT_SECRET) ? 'oauth' :
    'password';

// The address students see. Sending as osu@clubs.wusa.ca requires control of that
// domain's DNS, so the Cloudflare transport needs a from address on an onboarded domain.
const from = env.EMAIL_FROM ?? '"osu!uwaterloo" <osu@clubs.wusa.ca>';
const replyTo = env.EMAIL_REPLY_TO ?? undefined;

const office365Options = {
    host: 'smtp.office365.com',
    port: 587,
    secure: false, // port 587 starts plaintext and is upgraded via STARTTLS
    requireTLS: true,
};

let cachedToken: { value: string, expiresAt: number } | null = null;

// Fetch an access token for SMTP submission via the client credentials flow.
async function getAccessToken(): Promise<string> {
    // Reuse the cached token until it is within a minute of expiring
    if (cachedToken && Date.now() < cachedToken.expiresAt - 60 * 1000) {
        return cachedToken.value;
    }

    const url = `https://login.microsoftonline.com/${env.SMTP_OAUTH_TENANT_ID}/oauth2/v2.0/token`;
    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: env.SMTP_OAUTH_CLIENT_ID,
            client_secret: env.SMTP_OAUTH_CLIENT_SECRET,
            scope: 'https://outlook.office365.com/.default',
        }),
    });

    const body = await response.json() as any;

    if (!response.ok) {
        throw new Error(`Failed to get SMTP access token (${response.status}): ${body.error_description ?? body.error ?? 'unknown error'}`);
    }

    cachedToken = {
        value: body.access_token,
        expiresAt: Date.now() + (body.expires_in ?? 3600) * 1000,
    };

    return cachedToken.value;
}

let staticTransporter: Transporter | null = null;
let oauthTransporter: { transporter: Transporter, token: string } | null = null;

async function getTransporter(): Promise<Transporter> {
    if (mode === 'cloudflare') {
        staticTransporter ??= nodemailer.createTransport({
            host: 'smtp.mx.cloudflare.net',
            port: 465,
            secure: true, // port 465 is TLS from the first byte
            auth: {
                user: 'api_token',
                pass: env.CF_EMAIL_API_TOKEN,
            },
        });
        return staticTransporter;
    }

    if (mode === 'password') {
        staticTransporter ??= nodemailer.createTransport({
            ...office365Options,
            auth: {
                user: env.SMTP_EMAIL,
                pass: env.SMTP_PASSWORD,
            },
        });
        return staticTransporter;
    }

    // Rebuild the transporter whenever the token has been rotated
    const token = await getAccessToken();
    if (!oauthTransporter || oauthTransporter.token !== token) {
        oauthTransporter = {
            token,
            transporter: nodemailer.createTransport({
                ...office365Options,
                auth: {
                    type: 'OAuth2',
                    user: env.SMTP_EMAIL,
                    accessToken: token,
                },
            }),
        };
    }

    return oauthTransporter.transporter;
}

// Function to send email
export async function sendEmail(
    to: string,
    title: string,
    text: string,
    html: string
) {
    const mailOptions = {
        from: from,
        replyTo: replyTo,
        to: to,
        subject: title,
        text: text,
        html: html,
    };

    const transporter = await getTransporter();
    const info = await transporter.sendMail(mailOptions);

    console.log(`Email sent to ${to} via ${mode}: ${info.messageId}`);

    return info;
}
