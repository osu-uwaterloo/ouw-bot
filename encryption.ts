import crypto from 'crypto-js';
import env from './env.js';

const { AES, enc } = crypto;


export const encryptUserId = (userId: string) : string => {
    return AES.encrypt(userId, env.AES_ENCRYPTION_SECRET).toString().replace(/\//g, '_').replace(/\+/g, '-');
};

export const decryptUserId = (encryptedUserId: string | undefined) : string | null => {
    if (!encryptedUserId) return null;
    encryptedUserId = encryptedUserId.replace(/_/g, '/').replace(/-/g, '+');
    try {
        return AES.decrypt(encryptedUserId, env.AES_ENCRYPTION_SECRET).toString(enc.Utf8);
    } catch (e) {
        return null;
    }
};

export const generateRandomToken = (length: number = 16) : string => {
    return crypto.lib.WordArray.random(length).toString();
};
