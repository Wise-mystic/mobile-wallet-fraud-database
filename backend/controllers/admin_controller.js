import { AdminModel } from "../models/admin_model.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { adminSchema } from "../schema/admin_schema.js";




export const signUp = async (req, res, next) => {
    try {
        const { error, value } = adminSchema.validate(req.body);
        if (error) {
            return res.status(400).send(error.details[0].message);
        }

        //   Checking if user is already in database
        const email = value.email;

        const findIfAdminExist = await AdminModel.findOne({ email });
        if (findIfAdminExist) {
            return res.status(401).send("User is already registered");
        } else {
            const hashedPassword = bcrypt.hashSync(value.password, 12);
            value.password = hashedPassword;

            const addadmin = await AdminModel.create(value);
            return res.status(201).send("User registered successfully");
        }
    } catch (error) {
        next(error);
    }
};

export const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        const admin = await AdminModel.findOne({ email });

        if (!admin) {
            return res.status(401).json("Invalid email or password");
        }

        const correctPassword = bcrypt.compareSync(password, admin.password);
        if (!correctPassword) {
            return res.status(401).json("Invalid email or password");
        }

        req.session.admin = { id: admin.id };
        console.log("admin", req.session.admin);

        // Check if environment variables are set
        if (!process.env.JWT_PRIVATE_KEY || !process.env.REFRESH_TOKEN_SECRET) {
            throw new Error("JWT_PRIVATE_KEY or REFRESH_TOKEN_SECRET is not defined in environment variables.");
        }

        // Generate tokens
        const accessToken = jwt.sign(
            { id: admin._id },
            process.env.JWT_PRIVATE_KEY,
            // { expiresIn: "1h" }
        );
        const refreshToken = jwt.sign(
            { id: admin._id },
            process.env.REFRESH_TOKEN_SECRET,
            { expiresIn: "7d" }
        );

        res.status(200).json({
            message: "Login Successfully",
            token: accessToken,
            refreshToken: refreshToken,
        });
    } catch (error) {
        console.error("Error in login:", error.message);
        next(error);
    }};

// export const login = async (req, res, next) => {
//     try {
//         const { email, password } = req.body

//         const admin = await AdminModel.findOne({ email: email });

//         if (!admin) {
//             res.status(401).json('Invalid email or password');
//         } else {
//             const correctPassword = bcrypt.compareSync(password, admin.password);
//             if (!correctPassword) {
//                 res.status(401).json('Invalid email or password');
//             } else {
//                 req.session.admin = { id: admin.id };
//                 console.log('admin', req.session.admin);
//                 res.status(200).json('Login Successfully');
//             }
//         };

//         const accessToken = jwt.sign(
//             { id: admin._id },
//             process.env.JWT_PRIVATE_KEY,
//             {
//               expiresIn: "1h",
//             }
//           );
//           const refreshToken = jwt.sign(
//             { id: admin._id },
//             process.env.REFRESH_TOKEN_SECRET,
//             { expiresIn: "7d" }
//           );
  
//           res.json({
//             token: accessToken,
//             refreshToken: refreshToken,
//           });
//         }

        // const hashedPassword = bcrypt.hashSync(password, 8);

        // await AdminModel.create({
        //     // ...value,
        //     password: hashedPassword
        // });}

    // catch (error) {
    //         next(error);

    //     }
    // };



    export const listAdminUsers = async (req, res) => {
        try {
            const token = req.headers.authorization?.split(" ")[1];
            if (!token) {
                return res.status(403).json({ message: "You do not have permission to view this information." });
            }

            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            if (!decoded || !decoded.isAdmin) {
                return res.status(403).json({ message: "You do not have permission to view this information." });
            }

            const admins = await AdminModel.find({ isActive: true });
            res.status(200).json(
                admins.map((admin) => ({
                    name: admin.name,
                    email: admin.email,
                    phone: admin.phone,
                    permissions: admin.permissions,
                    status: admin.status,
                }))
            );
        } catch (error) {
            console.error("Error fetching admin users:", error);
            res.status(500).json({ message: "An error occurred while retrieving admin users." });
        }
    };
