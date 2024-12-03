import jwt from 'jsonwebtoken'
import { jwtKey } from '../config/index.config.js'

export const createTokens = async (payload) => {
    const accessToken = jwt.sign(payload, jwtKey.accessSecret, {
        expiresIn: jwtKey.accessTime,
    })
    const refreshToken = jwt.sign(payload, jwtKey.refreshSecret, {
        expiresIn: jwtKey.refreshTime,
    })
    return { accessToken, refreshToken }
}

export const verifyTokens = (type, token) => {
    const data = jwt.verify(
        token,
        type == 'access' ? jwtKey.accessSecret : jwtKey.refreshSecret,
    )
    return data
}
