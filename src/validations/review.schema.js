import { z } from 'zod'

export const reviewSchema = z.object({
    company_id: z.string().uuid(),
    rating: z.number(),
    comment: z.string().min(10),
    status: z.enum(['approved', 'pending', 'rejected']),
})
