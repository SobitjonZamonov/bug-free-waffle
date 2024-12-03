import app from './src/app.js'
import { application } from './src/config/index.config.js'
import { logger } from './src/utils/logger.utils.js'

const startApp = () => {
    try {
        app.listen(application.port, () => {
            logger.info(`Server running ${application.port} : port`)
        })
    } catch (error) {
        throw new Error(error)
    }
}

startApp()
