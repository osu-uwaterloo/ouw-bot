import * as wcag from 'wcag-contrast';

// Parse human boolean to boolean (true, Yes, Y, 1, t...)
export const parseHumanBool = (str: string | boolean | null | undefined, defaultValue:boolean = false): boolean => {
	if (typeof str === 'boolean') return str;
	if (str === null || str === undefined) return defaultValue;
	str = str.toLowerCase();
	if (defaultValue) {
		return !['false', 'no', 'n', '0', 'f'].includes(str);
	} else {
		return ['true', 'yes', 'y', '1', 't'].includes(str);
	}
}

// Parse hex colour to standard format (#fff, fff, fFf, 123456)
type HexColourString = `#${string}`;
export const parseHexColour = (str: string): HexColourString | null => {
	if (!str) return null;
	str = str.trim().toLowerCase();
	str = str.replace(/^#/, '');
	if (str.length === 3) {
		str = str[0] + str[0] + str[1] + str[1] + str[2] + str[2];
	}
	if (!/^[0-9a-f]{6}$/.test(str)) {
		return null;
	}
	return `#${str}`;	
}

// Calculate WCAG contrast ratio between two colours
export const calculateColourContrast = (colour1: string, colour2: string): number => {
	const contrast = wcag.hex(colour1, colour2);
	return contrast;
}