export async function generatePassword(length = 10) {
	const charSet =
		'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	let value = '';
	for (let i = 0, n = charSet.length; i < length; ++i) {
		value += charSet.charAt(Math.floor(Math.random() * n));
	}

	return value;
}
