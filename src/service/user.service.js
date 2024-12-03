import { db } from '../database/index.database.js'
import {
    comparePassword,
    generateHashPassword,
    createTokens,
    otpGenerator,
    sendMail,
    verifyTokens,
} from '../helpers/index.helpers.js'

export const registerUserService = async (userData) => {
    try {
        const { username, password, email } = userData;

        const existingUser = await db('users').where({ username }).first();
        if (existingUser) {
            throw new Error('User with this username already exists');
        }

        const otp = otpGenerator();
        await sendMail(
            email,
            'Your One-Time Password',
            `<h1><b>YOUR ONE-TIME PASSWORD IS => ${otp}</b></h1>`,
        );
        const hashedPassword = await generateHashPassword(password);

        const [newUser] = await db('users')
            .insert({ ...userData, password: hashedPassword })
            .returning(['id', 'username', 'email']);

        const otpCheck = await createOtp(otp, newUser.id);

        if (otpCheck.isTrue) {
            return { success: true, user: newUser };
        }

        return { success: false, error: otpCheck.error };
    } catch (error) {
        console.error('Error in registerUserService:', error.message);
        return { success: false, error: error.message };
    }
};

export const verifyUserService = async (userData) => {
    try {
        const { user_id, otp_code } = userData
        const { isExists, error, otp } = await findOtpById(user_id)

        if (!isExists) {
            return { success: false, error }
        }
        if (otp.otp_code != otp_code) {
            throw new Error('Otp is not valid')
        }
        const { isUpdated, err } = await updateUserStatus(user_id)

        if (!isUpdated) {
            throw new Error(err)
        }
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}
export const loginUserService = async (userData) => {
    try {
        const { username, password } = userData
        const [user] = await db('users').select('*').where('username', username)

        if (!user) {
            throw new Error('User not found')
        }
        const isEqualPassword = await comparePassword(password, user.password)
        if (!isEqualPassword) {
            throw new Error('Username or password not valid')
        }
        const payload = {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
        }
        const token = await createTokens(payload)
        return { success: true, token }
    } catch (error) {
        return { success: false, error }
    }
}
export const getUserProfileService = async (userData) => {
    try {
        const { username } = userData

        const user = await db('users').select('*').where('username', username)

        if (!user) {
            throw new Error('User not found')
        }
        delete user.password
        return { success: true, user }
    } catch (error) {
        return { success: false, error }
    }
}
export const updateTokenService = async (refreshToken) => {
    const decode = verifyTokens('refresh', refreshToken)
    delete decode.exp
    const token = await createTokens(decode)
    return token
}
export const forgetPasswordService = async (userData) => {
    try {
        const { email } = userData;

        const user = await db('users').select('*').where('email', email).first();
        if (!user) {
            throw new Error('User not found');
        }

        const otp = otpGenerator();
        const result = await updateOtp(user.id, otp);
        if (!result.isUpdated) {
            return { success: false, error: result.error };
        }

        const resetLink = `http://localhost:3000/api/v1/auth/change/password/${user.id}`;
        await sendMail(
            email,
            'Otp for change password',
            `<p><b>This key for updating your password: ${otp}</b></p>
             <p>Reset your password using this link: <a href="${resetLink}">${resetLink}</a></p>`
        );

        return { success: true };
    } catch (error) {
        console.error('Error in forgetPasswordService:', error.message);
        return { success: false, error: error.message };
    }
};

export const changePasswordService = async (data, userId) => {
    try {
        const { newPassword, userOtp } = data
        const otpData = await findOtpById(userId)
        if (userOtp != otpData.otp_code) {
            throw new Error('Otp code not valid')
        }
        const hashPassword = await generateHashPassword(newPassword)
        const result = await updateUserPassword(userId, hashPassword)
        const { isUpdated, error } = result

        if (!isUpdated) {
            return { success: false, error }
        }
        return { success: true }
    } catch (error) {
        return { success: true, error }
    }
}

export const getAllUsersService = async ({ limit, skip }) => {
    try {
        const users = await db('users').select('*').offset(skip).limit(limit)

        if (users.length == 0) {
            throw new Error('Users not found')
        }
        return { success: true, users }
    } catch (error) {
        return { success: false, error }
    }
}
export const searchUserService = async (query) => {
    try {
        const { username } = query
        const users = await db('users')
            .select('*')
            .where('username', 'ILIKE', `%${username}%`)
        if (users.length == 0) {
            return { success: true }
        }
        return { success: true, users }
    } catch (error) {
        return { success: true, error }
    }
}
export const getUserByIdService = async (userId) => {
    try {
        const [user] = await db('users').select('*').where('id', userId)
        if (!user) {
            throw new Error('User not found')
        }
        delete user.password
        return { success: true, user }
    } catch (error) {
        return { success: false, error }
    }
}
export const updateUserByIdService = async (userId, newData) => {
    try {
        const [user] = await db('users').select('*').where('id', userId)
        if (!user) {
            throw new Error('User not found')
        }
        const userPassword = newData?.password
        if (userPassword) {
            const hashPassword = await generateHashPassword(userPassword)
            newData.password = hashPassword
        }
        const newUser = await db('users')
            .where('id', userId)
            .update(newData)
            .returning('*')
        if (!newUser) {
            throw new Error('Error while updating user')
        }

        return { success: true, newUser }
    } catch (error) {
        return { success: false, error }
    }
}
export const deleteUserByIdService = async (userId) => {
    try {
        await db('users').where('id', userId).del()
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}

const createOtp = async (otp_code, user_id) => {
    try {
        await db('otp').insert({ otp_code, user_id });
        return { isTrue: true };
    } catch (error) {
        return { isTrue: false, error };
    }
};


const updateOtp = async (user_id, otp_code) => {
    try {
        await db('otp').where('user_id', user_id).update({ otp_code });
        return { isUpdated: true };
    } catch (error) {
        return { isUpdated: false, error };
    }
};

const findOtpById = async (user_id) => {
    try {
        const [otp] = await db
            .select('*')
            .from('otp')
            .where('user_id', '=', user_id)
        if (Object.keys(otp).length == 0) {
            throw new Error('Invalid user id')
        }
        return { isExists: true, otp }
    } catch (error) {
        return { isExists: true, error }
    }
}
const updateUserStatus = async (userId) => {
    try {
        await db('users').where('id', userId).update({ status: 'active' })
        return { isUpdated: true }
    } catch (err) {
        return { isUpdated: false, err }
    }
}

const updateUserPassword = async (userId, hashPassword) => {
    try {
        await db('users').where('id', userId).update({ password: hashPassword })
        return { isUpdated: true }
    } catch (err) {
        return { isUpdated: false, err }
    }
}
