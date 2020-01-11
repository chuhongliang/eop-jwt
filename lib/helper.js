const jwt = require('jsonwebtoken');

class Helper {
	verify(token, opts) {
		return new Promise((resolve, reject) => {
			jwt.verify(token, opts, (err, decode) => {
				if (err) {
					reject(err);
				} else {
					resolve(decode);
				}
			});
		});
	}

	async getSecret(provider, token) {
		const decoded = decode(token, { complete: true });
		if (!decoded || !decoded.header) {
			throw new Error('Invalid token');
		}
		return provider(decoded.header, decoded.payload);
	}

	resolveAuthHeader(ctx, opts) {
		let token;
		if (!ctx.header || !ctx.header.authorization) {
			return;
		}
		const parts = ctx.header.authorization.split(' ');
		if (parts.length === 2) {
			const scheme = parts[0];
			const credentials = parts[1];
			if (/^Bearer$/i.test(scheme)) {
				token = credentials;
				return token;
			}
		}
		if (!opts.passthrough) {
			ctx.throw(401, 'Bad Authorization header format. Format is "Authorization: Bearer <token>"');
		}
	}

	resolveCookies(ctx, opts) {
		return opts.cookie && ctx.cookies.get(opts.cookie);
	}
}
module.exports = new Helper();





