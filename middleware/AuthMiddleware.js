import { verifyToken } from '../utils/TokenGenerators';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function tokenHandler(req, res, next) {
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

		// Set the user
		req.user = user;

		next();
	} catch (err) {
		console.error(err);
		return res.status(500).json({ msg: 'Server error' });
	}
}
