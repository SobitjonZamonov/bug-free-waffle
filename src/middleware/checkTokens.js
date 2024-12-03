import { verifyTokens } from '../helpers/index.helpers.js'
import { logger, statusCode } from '../utils/index.utils.js'

export const checkToken = (req, res, next) => {
    try {
        const bearerToken = req.headers?.authorization

        if (!bearerToken || !bearerToken.startsWith('Bearer')) {
            return res
                .status(statusCode.UNAUTHORIZED)
                .send('Authentication is required in bearer token')
        }
        const token = bearerToken.split(' ')[1]
        const decode = verifyTokens('access', token)
        req.user = decode
        next()
    } catch (err) {
        logger.error('Error in token verification:', err)
        return res.status(statusCode.INTERNAL_SERVER_ERROR).json({
            error: 'Server error while verifying token',
        })
    }
}
