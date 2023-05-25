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
