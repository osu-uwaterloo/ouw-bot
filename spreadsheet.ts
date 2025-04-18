import env from './env.js';
import { GoogleSpreadsheet } from 'google-spreadsheet';
import { JWT } from 'google-auth-library';
import { GoogleSpreadsheetRow } from 'google-spreadsheet';
import { DateTime } from 'luxon';


const SCOPES = [
    'https://www.googleapis.com/auth/spreadsheets',
    'https://www.googleapis.com/auth/drive.file',
];

const jwt = new JWT({
    email: env.GOOGLE_CLIENT_EMAIL,
    key: env.GOOGLE_PRIVATE_KEY,
    scopes: SCOPES,
});

console.log("Loading Google Sheet integration...");

const doc = new GoogleSpreadsheet(env.GOOGLE_SHEET_ID, jwt);

await doc.loadInfo();

console.log(`Google Sheet integration loaded, sheet name: ${doc.title}`);

const memberSheet = doc.sheetsByIndex[0];

// Functions to interact with the Google Sheet
const findRowByKeyValue = async (key: string, value: string) : Promise<GoogleSpreadsheetRow | null> => {
    const rows = await memberSheet.getRows();
    return rows.find(row => row.get(key) === value) || null;
};

const findRowsByKeyValue = async (key: string, value: string) : Promise<GoogleSpreadsheetRow[]> => {
    const rows = await memberSheet.getRows();
    return rows.filter(row => row.get(key) === value);
}

const findRowByIndex = async (index: number) : Promise<GoogleSpreadsheetRow> => {
    const rows = await memberSheet.getRows();
    return rows[index];
}

type KeyValuePair = [string, any];
type KeyValuePairs = KeyValuePair[];


const tryFindRowsByMultipleKeyValues = async (keyValues: KeyValuePairs) : Promise<GoogleSpreadsheetRow[]> => {
    const rows = await memberSheet.getRows();
    for (const [key, value] of keyValues) {
        if (value === undefined || value === null) {
            continue;
        }
        const res = rows.filter(row => row.get(key) === value);
        if (res.length > 0) {
            return res;
        }
    }
    return [];
}

const tryFindRowByMultipleKeyValues = async (keyValues: KeyValuePairs) : Promise<GoogleSpreadsheetRow | null> => {
    const res = await tryFindRowsByMultipleKeyValues(keyValues);
    if (res.length > 0) {
        return res[0];
    } else {
        return null;
    }
}

const getAllRows = async () => {
    return await memberSheet.getRows();
};

const addRow = async (data: any) => {
    // data is an object with keys corresponding to the columns
    // e.g. { name: 'meow', email: 'meow@nya.com' }
    return await memberSheet.addRow(data);
}

const updateRow = async (row: GoogleSpreadsheetRow, data: any) => {
    // data is an object with keys corresponding to the updated columns
    // e.g. { name: 'purr' }
    row.assign(data);
    await row.save();
};

const deleteRow = async (row: GoogleSpreadsheetRow) => {
    await row.delete();
};


// Wrapped member management functions
const addMember = async (
    discordId: string,
    discordUsername: string,
    watiam: string
) => {
    const date = new Date();
    const isoTime = date.toISOString();
    const localTime = DateTime.fromJSDate(date).setZone('America/Toronto').toFormat('M/d/yyyy HH:mm:ss');
    return await addRow({
        timestamp: isoTime,
        local_time: localTime,
        discord_id: discordId,
        discord_username: discordUsername,
        watiam,
    });
}

// Key-value storage emulated
const kvSheet = doc.sheetsByIndex[1];
const kvGet = async (key: string) => {
    const rows = await kvSheet.getRows();
    const row = rows.find(row => row.get('key') === key);
    if (row) {
        return row.get('value');
    } else {
        return null;
    }
}

const kvSet = async (key: string, value: string) => {
    const rows = await kvSheet.getRows();
    const row = rows.find(row => row.get('key') === key);
    if (row) {
        row.assign({ value });
        await row.save();
    } else {
        await kvSheet.addRow({ key, value });
    }
}

export {
    findRowByKeyValue,
    findRowsByKeyValue,
    findRowByIndex,
    tryFindRowsByMultipleKeyValues,
    tryFindRowByMultipleKeyValues,
    getAllRows,
    addRow,
    updateRow,
    deleteRow,
    
    addMember,

    kvGet,
    kvSet
};