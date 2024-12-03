import { z } from 'zod'
export const wishlistScheme = z.object({
    user_id: z.string().uuid(),
    company_id: z.string().uuid(),
})
