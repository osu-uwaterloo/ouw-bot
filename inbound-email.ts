import { dkimVerify, type DKIMVerifyResult } from 'mailauth';
import PostalMime from 'postal-mime';

export const VERIFICATION_SUBJECT_PREFIX = '[OUW Verify]';
export const VERIFICATION_TOKEN_PATTERN = /\[OUW Verify\]\s+([a-f0-9]{32})\b/i;

export type WaterlooSender =
    | { kind: 'watiam', address: string, watiam: string }
    | { kind: 'friendly', address: string }
    | { kind: 'invalid', address: string }
    | { kind: 'outside-uw', address: string };

export interface ParsedVerificationEmail {
    tokens: string[];
    sender: WaterlooSender;
}

export function extractVerificationTokens(subject?: string, text?: string): string[] {
    const tokens = [subject, text].flatMap(value => {
        if (!value) return [];
        const pattern = new RegExp(VERIFICATION_TOKEN_PATTERN.source, 'gi');
        return Array.from(value.matchAll(pattern), match => match[1].toLowerCase());
    });
    return [...new Set(tokens)];
}

export function extractVerificationToken(subject?: string, text?: string): string | null {
    return extractVerificationTokens(subject, text)[0] ?? null;
}

export function classifyWaterlooSender(address: string): WaterlooSender {
    const normalizedAddress = address.trim().toLowerCase();
    const separator = normalizedAddress.lastIndexOf('@');
    if (separator <= 0) {
        return { kind: 'invalid', address: normalizedAddress };
    }

    const localPart = normalizedAddress.slice(0, separator);
    const domain = normalizedAddress.slice(separator + 1);
    if (domain !== 'uwaterloo.ca') {
        return { kind: 'outside-uw', address: normalizedAddress };
    }

    // Waterloo friendly addresses are firstname.lastname@uwaterloo.ca. The
    // canonical WatIAM is a 3-8 character, letter-led alphanumeric username.
    if (localPart.includes('.')) {
        return { kind: 'friendly', address: normalizedAddress };
    }
    if (/^[a-z][a-z0-9]{2,7}$/.test(localPart)) {
        return { kind: 'watiam', address: normalizedAddress, watiam: localPart };
    }
    return { kind: 'invalid', address: normalizedAddress };
}

export function getWaterlooDkimStatus(result: DKIMVerifyResult) {
    return {
        pass: result.results.some(signature =>
            signature.status.result === 'pass' &&
            signature.signingDomain.toLowerCase().replace(/\.$/, '') === 'uwaterloo.ca'
        ),
        temporaryError: result.results.some(signature =>
            signature.status.result === 'temperror' || signature.status.result === 'temperr'
        ),
    };
}

export async function parseVerificationEmail(raw: Buffer): Promise<ParsedVerificationEmail> {
    const email = await PostalMime.parse(raw, {
        maxHeadersSize: 128 * 1024,
        maxNestingDepth: 10,
        maxRfc822NestingDepth: 2,
    });

    const fromHeaders = email.headers.filter(header => header.key === 'from');
    const fromAddress = email.from && 'address' in email.from ? email.from.address : '';
    const sender = fromHeaders.length === 1 && fromAddress
        ? classifyWaterlooSender(fromAddress)
        : { kind: 'invalid' as const, address: fromAddress?.toLowerCase() ?? '' };
    return {
        tokens: extractVerificationTokens(email.subject, email.text),
        sender,
    };
}

export async function verifyWaterlooDkim(raw: Buffer) {
    return getWaterlooDkimStatus(await dkimVerify(raw));
}
