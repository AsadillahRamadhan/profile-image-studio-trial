import express from 'express';
import { PrismaClient, Prisma } from '@prisma/client';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import multer from 'multer';
import fs from 'fs';

const prisma = new PrismaClient();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, './upload/');
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    },
});

const upload = multer({ storage: storage });

app.post('/login', async (req, res) => {
    const { username, password } = req.body || undefined;

    if(!username || !password){
        return res.send({"message": "Username and Password is mandatory!"});
    }

    const user = await prisma.user.findFirst({
        where: {
            username: username
        },
    });

    if(!user){
        return res.send({"message": "These credentials doesn't match out records!"});
    }

    const result = await bcrypt.compare(password, user.password);

    if(!result){
        return res.send({"message": "These credentials doesn't match out records!"});
    }

    const access_token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET_KEY);
    const response = {access_token};
    return res.send(response)
});


app.post('/register', upload.single('avatar'),  async (req, res) => {
    let avatar = req.file || undefined;
    if(avatar){
        avatar = avatar.destination + avatar.filename;
    }
    const { username, password, email, name } = req.body || undefined;
    if(username && password && avatar && email && name){
        const prev = await prisma.user.findFirst({
            where: {
                username: username
            },
        });
        if(prev){
            fs.unlinkSync(avatar);
            return res.send({"message": "User already defined!"});
        }

        const user = await prisma.user.create({
            data: {
                username: username,
                email: email,
                name: name,
                avatar: avatar,
                password: await bcrypt.hash(password, 10)
            }
        });

        if(user){
            const access_token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET_KEY);
            const response = {access_token};
            return res.send(response)
        }
    } else {
        fs.unlinkSync(avatar.path);
        return res.send({"message": "Fill all of those credentials!"});
    }
});

app.use((req, res, next) => {
    if(!req.headers['authorization']){
        return res.send({"message": "Insert token!"});
    }
    const access_token = req.headers['authorization'].split(' ')[1];

    jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET_KEY, async (err, payload) => {
        if(err){
            return res.send({"message": "Token unmatched!"});
        }
        const {id, username, email, name, avatar, password} = payload;

        const user = await prisma.user.findFirst({where: {id, username, email, name, avatar, password}});

        if(!user){
            return res.send({"message": "This token is no longer available!"});
        }
        return next();
    });

});

app.get('/get-credentials', (req, res) => {
    const access_token = req.headers['authorization'].split(' ')[1];
    let user;
    jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET_KEY, (err, payload) => {
        user = payload;
        delete user.password;
        delete user.iat;
        delete user.id;
    });

    return res.send(user);
});

app.put('/change-credentials', upload.single('avatar'), (req, res) => {
    let avatar = req.file || undefined;
    const { username, password, email, name } = req.body || undefined;
    const access_token = req.headers['authorization'].split(' ')[1];
    jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET_KEY, async (err, payload) => {
        if(password){
            password = await bcrypt.hash(password, 10);
        }

        if(avatar){
            fs.unlinkSync(payload.avatar);
            avatar = avatar.destination + avatar.filename;
        }

        await prisma.user.update({
            where: {
                id: payload.id,
            },
            data: {
                name: name || payload.name,
                username: username || payload.username,
                email: email || payload.email,
                password: password || payload.password,
                avatar: avatar || payload.avatar
            },
        })

        const user = await prisma.user.findUnique({
            where: {
              id: payload.id,
            },
          })

        return res.send({
            "message": "Updated!",
            "data": user,
            "access_token": jwt.sign(user, process.env.ACCESS_TOKEN_SECRET_KEY)
        });
    });
});

app.delete('/delete-account', (req, res) => {
    const access_token = req.headers['authorization'].split(' ')[1];
    jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET_KEY, async (err, payload) => {
        fs.unlinkSync(payload.avatar);
        await prisma.user.delete({
            where: {
             id: payload.id
            },
        });

        return res.send({"message": "User successfully deleted!"});
    });
});

app.post('/project', async (req, res) => {
    const {name} = req.body;

    if(!name){
        return res.send({"message": "Fill the project name!"});
    }

    const project = await prisma.project.create({
        data: {
            project_name: name
        }
    });

    if(!project){
        return res.send({"message": "The data is not stored!"});
    }

    return res.send({"message": "Data successfully stored!"});
});

app.get('/projects', async (req, res) => {
    const projects = await prisma.project.findMany({
        include: {
            tasks: {
                select: {
                    task_name: true,
                    user: {
                        select: {
                            name: true
                        }
                    }
                }
            }
        }
    });

    return res.send(projects);
});

app.get('/project/:projectId', async (req, res) => {
    const project = await prisma.project.findUnique({
        where: {
            id: parseInt(req.params.projectId)
        },
        include: {
            tasks: {
                select: {
                    task_name: true,
                    user: {
                        select: {
                            name: true
                        }
                    }
                }
            }
        }
    });

    if(!project){
        return res.send({"message": "Data not found!"});
    }
    return res.send(project);
});

app.put('/project/:projectId', async (req, res) => {
    const { name } = req.body;

    if(!name){
        return res.send({"message": "Insert the project name!"});
    }

    try {
        const project = await prisma.project.update({
            where: {
                id: parseInt(req.params.projectId)
            },
            data: {
                project_name: name
            }
        });
        return res.send(project);
    } catch (e){
        return res.send({"message": "Data not found!"});
    }

    
});

app.delete('/project/:projectId', async (req, res) => {
    try {
        await prisma.project.delete({
            where: {
             id: parseInt(req.params.projectId)
            },
        });

        return res.send({"message": "Successfully deleted!"});
    } catch (e){
        return res.send({"message": "Error deleting!"});
    }
});

app.post('/task', async (req, res) => {
    const {name, project_id} = req.body;
    const access_token = req.headers['authorization'].split(' ')[1];

    if(!name || !project_id){
        return res.send({"message": "Fill the data!"});
    }

    jwt.verify(access_token, process.env.ACCESS_TOKEN_SECRET_KEY, async (err, payload) => {
        const project = await prisma.project.findFirst({
            where: {
                id: parseInt(project_id)
            }
        });

        if(!project){
            return res.send({"message": "Project not found!"});
        }
        try {
            await prisma.task.create({
                data: {
                    task_name: name,
                    project_id: parseInt(project_id),
                    user_id: parseInt(payload.id)
                }
            });
        } catch (e){
            return res.send({"message": "Error storing data!"});
        }
        return res.send({"message": "Data successfully stored!"});
    });
});

app.get('/tasks', async (req, res) => {
    const tasks = await prisma.task.findMany({
        include: {
            user: {
                select: {
                    name: true
                }
            },
            project: {
                select: {
                    project_name: true
                }
            }
        }
    });

    if(!tasks){
        return res.send({"message": "No data available!"});
    }
    return res.send(tasks);
});

app.get('/task/:taskId', async (req, res) => {
    const task = await prisma.task.findFirst({
        where: {
            id: parseInt(req.params.taskId)
        },
        include: {
            user: {
                select: {
                    name: true
                }
            },
            project: {
                select: {
                    project_name: true
                }
            }
        }
    });

    if(!task){
        return res.send({"message": "Task not found!"});
    }
    return res.send(task);
});

app.put('/task/:taskId', async (req, res) => {
    const { name } = req.body;

    if(!name){
        return res.send({"message": "Fill the data!"});
    }

    try {
        const task = await prisma.task.update({
            where: {
                id: parseInt(req.params.taskId)
            },
            data: {
                task_name: name
            }
        });
        return res.send(task);
    } catch (e){
        return res.send({"message": "Data not found!"});
    }
});

app.delete('/task/:taskId', async (req, res) => {
    try {
        await prisma.task.delete({
            where: {
             id: parseInt(req.params.taskId)
            },
        });

        return res.send({"message": "Successfully deleted!"});
    } catch (e){
        return res.send({"message": "Data not found!"});
    }
});


app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});