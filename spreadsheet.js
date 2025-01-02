import env from './env.js';
import { GoogleSpreadsheet } from 'google-spreadsheet';
import { JWT } from 'google-auth-library'


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

console.log("Google Sheet integration loaded", doc.title);

const memberSheet = doc.sheetsByIndex[0];

// Functions to interact with the Google Sheet
const findRowByKeyValue = async (key, value) => {
    const rows = await memberSheet.getRows();
    return rows.find(row => row.get(key) === value);
};

const findRowsByKeyValue = async (key, value) => {
    const rows = await memberSheet.getRows();
    return rows.filter(row => row.get(key) === value);
}

const findRowByIndex = async (index) => {
    const rows = await memberSheet.getRows();
    return rows[index];
}

const tryFindRowsByMultipleKeyValues = async (keyValues) => {
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

const tryFindRowByMultipleKeyValues = async (keyValues) => {
    const res = await tryFindRowsByMultipleKeyValues(keyValues);
    if (res.length > 0) {
        return res[0];
    } else {
        return undefined;
    }
}

const getAllRows = async () => {
    return await memberSheet.getRows();
};

const addRow = async (data) => {
    // data is an object with keys corresponding to the columns
    // e.g. { name: 'meow', email: 'meow@nya.com' }
    return await memberSheet.addRow(data);
}

const updateRow = async (row, data) => {
    // data is an object with keys corresponding to the updated columns
    // e.g. { name: 'purr' }
    row.assign(data);
    await row.save();
};

const deleteRow = async (row) => {
    await row.delete();
};


// Wrapped member management functions
const addMember = async (discordId, discordUsername, watiam) => {
    const date = new Date();
    const isoTime = date.toISOString();
    const localTime = `${date.getDate()}/${date.getMonth() + 1}/${date.getFullYear()} ${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`;
    return await addRow({
        timestamp: isoTime,
        local_time: localTime,
        discord_id: discordId,
        discord_username: discordUsername,
        watiam,
    });
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
    
    addMember
};