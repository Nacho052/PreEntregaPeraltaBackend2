import CustomRouter from "../../utils/CustomRouter.util.js";
import { fork } from "child_process"
import usersApiRouter from "./users.api.js";
//import cookiesRouter from "./cookies.api.js";
import sessionsApiRouter from "./sessions.api.js";
import productsApiRouter from "./products.api.js";
import cartsApiRouter from "./carts.api.js";


class ApiRouter extends CustomRouter {
    constructor() {
        super();
        this.init();
    }
    init = () => {
        this.use('/users', ['PUBLIC'], usersApiRouter);
        this.use('/products', ['PUBLIC'], productsApiRouter);
        this.use('/carts', ['PUBLIC'], cartsApiRouter);
        this.use('/sessions', ['PUBLIC'], sessionsApiRouter);
        this.read('/sum', ['PUBLIC'], (req, res) => {
            const child = fork('./src/utils/process.util.js')
            child.send('start')
            child.on('message', (response) => {
                const message = 'Sumatoria obtenida'
                return res.json200(response, message)
            })
        })
    };
}

const apiRouter = new ApiRouter();
export default apiRouter.getRouter();