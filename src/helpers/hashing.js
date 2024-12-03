import { hash, genSalt, compare } from 'bcrypt'

const generateSalt = async () => genSalt(10)

export const generateHashPassword = async (password) => {
    const salt = await generateSalt()
    const hashPassword = hash(password, salt)
    return hashPassword
}

export const comparePassword = async (userPassword, hashPassword) => {
    return compare(userPassword, hashPassword)
}
