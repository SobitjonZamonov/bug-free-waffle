import { db } from '../database/knex.js'
import { sendMail } from '../helpers/index.helpers.js'

export const sendMessageService = async (data, sender) => {
    try {
        const { receiver_id, message } = data
        const [user] = await db('users').select('*').where('id', receiver_id)
        if (!user) {
            throw new Error('User not found')
        }
        await sendMail(user.email, `message from ${sender.email}`, `${message}`)
        const msg = {
            sender_id: sender.id,
            receiver_id,
            message,
        }
        await db('message').insert(msg)
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}

export const getAllMessagesService = async ({ limit, skip }) => {
    try {
        const messages = await db('message')
            .select('*')
            .offset(skip)
            .limit(limit)
        if (messages.length == 0) {
            throw new Error('Messages not found')
        }
        return { success: true, messages }
    } catch (error) {
        return { success: false, error }
    }
}
export const getMessageService = async (messageId) => {
    try {
        const message = await db('message').where('id', messageId).select('*')
        if (message.length == 0) {
            throw new Error('Message not found')
        }
        return { success: true, message: message[0] }
    } catch (error) {
        return { success: false, error }
    }
}
export const updateMessageService = async (messageId, message) => {
    try {
        const msg = await db('message')
            .where('id', messageId)
            .update({ message })
            .returning('*')
        if (msg.length == 0) {
            throw new Error('Message not found')
        }
        return { success: true, msg }
    } catch (error) {
        return { success: false, error }
    }
}

export const deleteMessageService = async (messageId) => {
    try {
        await db('message').where('id', messageId).del()
        return { success: true }
    } catch (error) {
        return { success: false, error }
    }
}
