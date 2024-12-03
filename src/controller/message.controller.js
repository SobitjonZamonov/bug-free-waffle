import {
    deleteMessageService,
    getAllMessagesService,
    getMessageService,
    sendMessageService,
    updateMessageService,
} from '../service/index.service.js'
import { statusCode } from '../utils/statuscodes.js'

export const sendMessage = async (req, res, next) => {
    try {
        const data = { message: req.body.message, receiver_id: req.params.id }
        const { success, error } = await sendMessageService(data, req.user)

        if (success) {
            return res.status(statusCode.CREATED).send({
                message: 'Message sended',
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'fail',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
export const getAllMessages = async (req, res, next) => {
    try {
        const { success, error, messages } = await getAllMessagesService(
            req.pagination,
        )
        if (success) {
            return res.status(statusCode.OK).send({
                message: 'success',
                messages,
            })
        }
        return res.status(statusCode.INTERNAL_SERVER_ERROR).send({
            messages: 'fail',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
export const getMessage = async (req, res, next) => {
    try {
        const { success, error, message } = await getMessageService(
            req.params.id,
        )
        if (success) {
            return res.status(statusCode.OK).send({
                message: 'success',
                message,
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'fail',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
export const updateMessage = async (req, res, next) => {
    try {
        const { message } = req.body
        const { success, error, msg } = await updateMessageService(
            req.params.id,
            message,
        )
        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Updated',
                updatedMessage: msg,
            })
        }
        return res.status(statusCode.BAD_REQUEST).send({
            message: 'fail',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
export const deleteMessage = async (req, res, next) => {
    try {
        const { success, error } = await deleteMessageService(req.params.id)
        if (success) {
            return res.status(statusCode.OK).send({
                message: 'Deleted',
            })
        }
        res.status(statusCode.INTERNAL_SERVER_ERROR).send({
            message: 'fail',
            error: error.message,
        })
    } catch (error) {
        next(error)
    }
}
