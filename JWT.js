const { sign, verify } = require('jsonwebtoken');

const secretKey = "97b34701a945e7d7717fbf4d678f280766a6a64dc7662d7f68318f13d0fe01c085ab970eb17daa8138457f3dac983cd92a6f8e770462ef5ccbfd4d39d9a61bc4";

const createTokens = (user) => {
    const accessToken = sign(
        { username: user.username, id: user.id },
        secretKey,
        { expiresIn: '60m' }
    );
    return accessToken;
};

const validateToken = (req, res, next) => {
    const accessToken = req.cookies["access-token"];

    if (!accessToken) return res.status(400).json({ error: "User not authenticated!" });

    try {
        const validToken = verify(accessToken, secretKey);
        if (validToken) {
            req.authenticated = true;
            return next();
        }
    } catch (err) {
        return res.status(400).json({ error: err });
    }
};

module.exports = { createTokens, validateToken };

