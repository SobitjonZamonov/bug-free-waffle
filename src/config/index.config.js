import { config } from 'dotenv'
config()

export const application = {
    port: process.env.PORT,
    node_env: process.env.NODE_ENV,
}

export const database = {
    host: process.env.PG_HOST,
    port: process.env.PG_PORT,
    user: process.env.PG_USER,
    password: process.env.PG_PASSWORD,
    database: process.env.PG_DATABASE,
}

export const email = {
    user: process.env.USER_EMAIL,
    pass: process.env.APP_PASSWORD,
}

export const jwtKey = {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    accessTime: process.env.JWT_ACCESS_EXPIRES_IN,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshTime: process.env.JWT_REFRESH_EXPIRES_IN,
    forgetSecret: process.env.JWT_FORGET_PASSWORD_SECRET,
    forgetTime: process.env.JWT_FORGET_PASSWORD_EXPIRES_IN,
}
