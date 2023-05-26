import { generatePassword } from './PasswordGenerator';
import jwt from 'jsonwebtoken';

export async function generateToken(user) {
	const id = user.id;

	return await jwt.sign({ id }, process.env.JWT_SECRET, {
		expiresIn: '15min',
	});
}

export async function verifyToken(token) {
	return await jwt.verify(token, process.env.JWT_SECRET);
}

export async function generateRefreshToken(user) {
	const id = user.id;
	// Refresh tokens are good longer than access tokens
	return await jwt.sign({ id }, process.env.JWT_REFRESH_SECRET, {
		expiresIn: '7d',
	});
}

export async function verifyRefreshToken(token) {
	return await jwt.verify(token, process.env.JWT_REFRESH_SECRET);
}

export async function generateContext() {
	const context = generatePassword();
	const contextToken = await bcrypt.hash(context, 10);

	return { context, contextToken };
}

export async function verifyContext(context, contextToken) {
	return await bcrypt.compare(context, contextToken);
}

export async function getTokens(user) {
	const token = await generateToken(user);
	const refreshToken = await generateRefreshToken(user);
	const { context, contextToken } = await generateContext();

	return { token, refreshToken, context, contextToken };
}
