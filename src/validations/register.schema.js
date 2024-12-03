import { z } from 'zod'

export const registerSchema = z.object({
    name: z.string().min(2),
    username: z.string().min(4),
    email: z
        .string()
        .min(5, { message: 'Email not valid' })
        .email('Email not valid'),
    password: z.string().min(8),
})
