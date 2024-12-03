import { z } from 'zod'
import { logger } from '../utils/index.utils.js'
export const validationMiddleware = (schema) => {
    return (req, res, next) => {
        try {
            schema.parse(req.body)
            next()
        } catch (error) {
            if (error instanceof z.ZodError) {
                logger.error('validation error')
                return res.status(400).json({
                    error: 'validationError',
                    details: error.errors.map((err) => err.message),
                })
            }
            next(error)
        }
    }
}
