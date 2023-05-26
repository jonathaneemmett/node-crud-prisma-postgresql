import {
	verifyToken,
	verifyRefreshToken,
	verifyContext,
} from '../utils/TokenGenerators.js';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function tokenHandler(req, res, next) {
	const { context, refreshToken } = req.cookies;

	if (!context || !refreshToken)
		return res.status(401).json({ msg: 'Not authorized' });

	const token = req.headers.authorization?.split(' ')[1];
	if (!token)
		return res.status(401).json({ msg: 'No token, not authorized' });

	try {
		const decoded = await verifyToken(token);
		if (!decoded) return res.status(401).json({ msg: 'Not authorized' });

		// Get the user
		const user = await prisma.user.findUnique({
			where: {
				id: decoded.id,
			},
		});
		if (!user) return res.status(401).json({ msg: 'Not authorized' });

		// Verify the refresh token
		const decodedRefreshToken = await verifyRefreshToken(refreshToken);
		if (!decodedRefreshToken)
			return res.status(401).json({ msg: 'Not authorized' });

		// Verify the context
		const isContext = await verifyContext(context, user.context);
		if (!isContext) return res.status(401).json({ msg: 'Not authorized' });

		// Set the user
		req.user = user;

		next();
	} catch (err) {
		console.error(err);
		return res.status(500).json({ msg: 'Server error' });
	}
}

export async function adminHandler(req, res, next) {
	const { user } = req;
	if (!user) return res.status(401).json({ msg: 'Not authorized' });

	if (user.role !== 'admin') {
		return res.status(401).json({ msg: 'Not authorized' });
	}

	next();
}
