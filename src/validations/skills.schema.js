import { z } from 'zod'
export const skillsScheme = z.object({
    name: z.string().min(1),
    category_id: z.string().uuid(),
})
