import { Router } from 'express'
import {
    getAllWishlistsCon,
    getWishlistsByIdCon,
    createWishlistCon,
    updateWishlistCon,
    deleteWishlistCon,
} from '../controller/index.controller.js'
import {
    checkToken,
    pagination,
    roleGuard,
    validationMiddleware,
} from '../middleware/index.middleware.js'
import { wishlistScheme } from '../validations/wishlist.schema.js'
export const wishlistRouter = Router()
wishlistRouter.get(
    '/',
    checkToken,
    roleGuard('admin'),
    pagination,
    getAllWishlistsCon,
)
wishlistRouter.get('/:id', checkToken, getWishlistsByIdCon)
wishlistRouter.post(
    '/',
    checkToken,
    validationMiddleware(wishlistScheme),
    createWishlistCon,
)
wishlistRouter.put('/:id', checkToken, updateWishlistCon)
wishlistRouter.delete('/:id', checkToken, deleteWishlistCon)
