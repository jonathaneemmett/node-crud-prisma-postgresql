import { PrismaClient } from '@prisma/client';
import { hash, compare } from 'bcrypt';
import {
	getTokens,
	verifyContext,
	verifyRefreshToken,
} from '../utils/TokenGenerators.js';

const prisma = new PrismaClient();

export async function register(req, res, next) {
	const { name, email, password } = req.body;

	// Simple validation
	if (!name || !email || !password)
		return res.status(400).json({ msg: 'Please enter all fields' });

	// Check if the user exists
	const user = await prisma.user.findUnique({
		where: {
			email: email,
		},
	});
	if (user)
		return res
			.status(400)
			.json({ msg: 'That email address is already in use.' });

	// Create a new user
	const newUser = await prisma.user.create({
		data: {
			name: name,
			email: email,
			password: await hash(password, 10),
		},
	});

	// Get the tokens
	const { token, refreshToken, context, contextToken } = await getTokens(
		newUser,
	);

	// Save the context to the user in the database
	await prisma.user.update({
		where: {
			id: newUser.id,
		},
		data: {
			context: context,
		},
	});

	// Bake the cookies
	res.cookie('refreshToken', refreshToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	res.cookie('context', context, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	// Return the user and the token to the client
	res.status(201).json({
		user: {
			id: newUser.id,
			name: newUser.name,
			email: newUser.email,
			role: newUser.role,
		},
		token: token,
	});
}

export async function login(req, res, next) {
	const { email, password } = req.body;

	// Simple validation
	if (!email || !password)
		return res.status(400).json({ msg: 'Please enter all fields' });

	// Get the user
	const user = await prisma.user.findUnique({
		where: {
			email: email,
		},
	});
	if (!user)
		return res
			.status(400)
			.json({ msg: 'Username or password is incorrect.' });

	// Validate password
	const isMatch = await compare(password, user.password);
	if (!isMatch)
		return res
			.status(400)
			.json({ msg: 'Username or password is incorrect.' });

	// Get the tokens
	const { token, refreshToken, context, contextToken } = await getTokens(
		user,
	);

	// Save the context to the user in the database
	await prisma.user.update({
		where: {
			id: newUser.id,
		},
		data: {
			context: context,
		},
	});

	// Bake the cookies
	res.cookie('refreshToken', refreshToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	res.cookie('context', contextToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	// Return the user and the token to the client
	res.status(200).json({
		user: {
			id: user.id,
			name: user.name,
			email: user.email,
			role: user.role,
		},
		token: token,
	});
}

export async function logout(req, res, next) {
	// Bake the cookies
	res.cookie('refreshToken', '', {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	res.cookie('context', '', {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});
}

export async function refreshToken(req, res, next) {
	const { context, refreshToken } = req.cookies;

	if (!refreshToken || !context)
		return res.status(401).json({ msg: 'Unauthorized' });

	// Decode the the refresh token
	const decodedRefreshToken = await verifyRefreshToken(refreshToken);
	if (!decodedRefreshToken)
		return res.status(401).json({ msg: 'Unauthorized' });

	// Get the user from the refresh token
	const user = await prisma.user.findUnique({
		where: {
			id: decodedRefreshToken.id,
		},
	});
	if (!user) return res.status(401).json({ msg: 'Unauthorized' });

	// Check if the context matches
	const isContext = await verifyContext(context, user.context);
	if (!isContext) return res.status(401).json({ msg: 'Unauthorized' });

	// Get the tokens
	const {
		token,
		refreshToken: newRefreshToken,
		context: newContext,
		contextToken: newContextToken,
	} = await getTokens(user);

	// Save the context to the user in the database
	await prisma.user.update({
		where: {
			id: user.id,
		},
		data: {
			context: newContext,
		},
	});

	// Bake the cookies
	res.cookie('refreshToken', refreshToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	res.cookie('context', contextToken, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: process.env.NODE_ENV === 'production',
		maxAge: 60 * 60 * 24 * 1, // 1 day
	});

	// Return the user and the token to the client
	res.status(200).json({
		user: {
			id: user.id,
			name: user.name,
			email: user.email,
			role: user.role,
		},
		token: token,
	});
}

export default { register, login, logout };
