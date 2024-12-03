import { z } from 'zod'

export const verifySchema = z.object({
    user_id: z.string().min(30),
    otp_code: z.string().min(6),
})
