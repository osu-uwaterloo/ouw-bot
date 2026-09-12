import assert from 'node:assert/strict';
import test from 'node:test';
import type { DKIMVerifyResult } from 'mailauth';
import {
    classifyWaterlooSender,
    extractVerificationToken,
    extractVerificationTokens,
    getWaterlooDkimStatus,
    parseVerificationEmail,
} from './inbound-email.js';

test('extracts a verification token from the subject or text body', () => {
    const token = '0123456789abcdef0123456789abcdef';
    assert.equal(extractVerificationToken(`[OUW Verify] ${token}`), token);
    assert.equal(extractVerificationToken('Email verification', `OUW-VERIFY\n[OUW Verify] ${token}`), token);
    assert.equal(extractVerificationToken('[OUW Verify] too-short'), null);
});

test('keeps valid codes from both the subject and body', () => {
    const staleToken = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const validToken = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    assert.deepEqual(
        extractVerificationTokens(
            `[OUW Verify] ${staleToken}`,
            `Verification code: [OUW Verify] ${validToken}`,
        ),
        [staleToken, validToken],
    );
});

test('classifies WatIAM, friendly, and non-Waterloo senders', () => {
    assert.deepEqual(classifyWaterlooSender('S2333LIN@uwaterloo.ca'), {
        kind: 'watiam',
        address: 's2333lin@uwaterloo.ca',
        watiam: 's2333lin',
    });
    assert.deepEqual(classifyWaterlooSender('solara.lin@uwaterloo.ca'), {
        kind: 'friendly',
        address: 'solara.lin@uwaterloo.ca',
    });
    assert.equal(classifyWaterlooSender('student@gmail.com').kind, 'outside-uw');
    assert.equal(classifyWaterlooSender('not an address').kind, 'invalid');
});

test('only accepts a passing uwaterloo.ca DKIM signature', () => {
    const result = (domain: string, status: 'pass' | 'fail' | 'temperror'): DKIMVerifyResult => ({
        headerFrom: ['uwaterloo.ca'],
        envelopeFrom: false,
        results: [{
            signingDomain: domain,
            status: { result: status },
            info: '',
        }],
    });

    assert.deepEqual(getWaterlooDkimStatus(result('uwaterloo.ca', 'pass')), {
        pass: true,
        temporaryError: false,
    });
    assert.equal(getWaterlooDkimStatus(result('example.com', 'pass')).pass, false);
    assert.equal(getWaterlooDkimStatus(result('uwaterloo.ca', 'fail')).pass, false);
    assert.equal(getWaterlooDkimStatus(result('uwaterloo.ca', 'temperror')).temporaryError, true);
});

test('parses the token and WatIAM from a raw message', async () => {
    const token = '0123456789abcdef0123456789abcdef';
    const raw = Buffer.from([
        'From: Student <s2333lin@uwaterloo.ca>',
        'To: verify@ouw.s23.moe',
        `Subject: [OUW Verify] ${token}`,
        'Content-Type: text/plain; charset=utf-8',
        '',
        `[OUW Verify] ${token}`,
    ].join('\r\n'));

    assert.deepEqual(await parseVerificationEmail(raw), {
        tokens: [token],
        sender: {
            kind: 'watiam',
            address: 's2333lin@uwaterloo.ca',
            watiam: 's2333lin',
        },
    });
});

test('rejects an ambiguous message with duplicate From headers', async () => {
    const token = '0123456789abcdef0123456789abcdef';
    const raw = Buffer.from([
        'From: Student <s2333lin@uwaterloo.ca>',
        'From: Attacker <attacker@example.com>',
        'To: verify@ouw.s23.moe',
        `Subject: [OUW Verify] ${token}`,
        '',
        'test',
    ].join('\r\n'));

    const parsed = await parseVerificationEmail(raw);
    assert.equal(parsed.sender.kind, 'invalid');
});
