import fs from 'fs';

let env: any = {};

// try reading env.json
try {
	env = JSON.parse(fs.readFileSync('./env.json', 'utf8'));
} catch (e) {
	console.log('No env.json file found, reading from process.env');
	env = process.env;
}

export default env;