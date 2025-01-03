// parse human boolean to boolean (true, Yes, Y, 1, t...)
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