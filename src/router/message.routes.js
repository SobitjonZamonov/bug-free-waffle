import { Router } from 'express'
import {
    deleteMessage,
    getAllMessages,
    getMessage,
    sendMessage,
    updateMessage,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { messageSchema } from '../validations/message.schema.js'

export const messageRouter = Router()

messageRouter.post(
    '/send/:id',
    checkToken,
    validationMiddleware(messageSchema),
    sendMessage,
)
messageRouter.get(
    '/',
    checkToken,
    roleGuard('admin'),
    pagination,
    getAllMessages,
)
messageRouter.get('/:id', checkToken, roleGuard('admin'), getMessage)
messageRouter.put('/:id', checkToken, roleGuard('admin'), updateMessage)
messageRouter.delete('/:id', checkToken, roleGuard('admin'), deleteMessage)
