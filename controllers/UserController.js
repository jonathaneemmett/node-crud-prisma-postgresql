import { Prisma, PrismaClient } from '@prisma/client';
import { hash, compare } from 'bcrypt';
import jwt from 'jsonwebtoken';

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

	// Token
	const token = jwt.sign({ id: newUser.id }, process.env.JWT_SECRET, {
		expiresIn: 3600,
	});

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

	// Token
	const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
		expiresIn: 3600,
	});

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

export default { register };
