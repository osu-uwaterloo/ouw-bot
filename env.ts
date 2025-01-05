import fs from 'fs';

let env: any = {};

// try reading env.json
try {
	env = JSON.parse(fs.readFileSync('./env.json', 'utf8'));
} catch (e) {
	console.log('No env.json file found, reading from process.env');
	try {
		env = JSON.parse(process.env?.CONFIG_JSON as string);
	} catch (e) {
		console.log('No process.env.CONFIG_JSON found! Please check your environment variables');
	}
}

export default env;