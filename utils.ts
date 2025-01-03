// parse human boolean to boolean (true, Yes, Y, 1, t...)
export const parseHumanBool = (str: string, defaultValue = false): boolean => {
	str = str.toLowerCase();
	if (defaultValue) {
		return !['false', 'no', 'n', '0', 'f'].includes(str);
	} else {
		return ['true', 'yes', 'y', '1', 't'].includes(str);
	}
}