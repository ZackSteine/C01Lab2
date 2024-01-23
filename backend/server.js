import express from "express";
import { MongoClient, ObjectId } from "mongodb";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const PORT = 4000;
const mongoURL = "mongodb://127.0.0.1:27017";
const dbName = "quirknotes";
const COLLECTIONS = {
    notes: "notes",
    users: "users"
}

let db;

async function connectToMongo() {
    const client = new MongoClient(mongoURL);

    try {
        await client.connect();
        console.log("Connected to MongoDB");

        db = client.db(dbName);
    } catch (error) {
        console.error("Error connecting to MongoDB", error);
    }
}

await connectToMongo();

function verifyRequestAuth(req, callback) {
    const token = req.headers.authorization.split(" ")[1];
    jwt.verify(token, "secret-key", callback);
}

app.listen(PORT, () => {
    console.log(`Server is running on http://127.0.0.1:${PORT}`)
});

app.post("/registerUser", express.json(), async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ error: "Username and password both needed to register."})
        }

        // Checking if username does not already exist in database
        const userCollection = db.collection(COLLECTIONS.users);
        const existingUser = await userCollection.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "Username already exists." });
        }

        // Creating hashed password
        const hashedPassword = await bcrypt.hash(password, 10);
        await userCollection.insertOne({
            username,
            password: hashedPassword
        });

        // Returning JSON Web Token
        const token = jwt.sign({ username }, 'secret-key', { expiresIn: "1h" });
        res.status(201).json({ response: "User registered successfully.", token });
    } catch (error) {
        res.status(500).json({ error: error.message })
    }
});

app.post("/loginUser", express.json(), async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res
                .status(400)
                .json({ error: "Username and password both needed to login." });
        }

        // FInd username in database
        const userCollection = db.collection(COLLECTIONS.users);
        const user = await userCollection.findOne({ username });

        // Validate user against hashed password inn database
        if (user && (await bcrypt.compare(password, user.password))) {
            const token = jwt.sign({ username }, "secret-key", { expiresIn: "1h" });

            // Send JSON Web Token to valid user
            res.json({ response: "User logged in successfully.", token: token });
        } else {
            res.status(401).json({ error: "Authentication failed." });
        }

    } catch {
        res.status(500).json({ error: error.message });
    }
});

app.post("/postNote", express.json(), async (req, res) => {
    try {
        const {title, content} = req.body;
        if (!title || !content) {
            return res
                .status(400)
                .json({error: "Title and content are both required."});
        }

        verifyRequestAuth(req, async (err, decoded) => {
            if (err) {
                return res.status(401).send("Unauthorized.");
            }

            const collection = db.collection(COLLECTIONS.notes);
            const result = await collection.insertOne({
                title,
                content,
                username: decoded.username
            });
            res.json({
                response: "Note added successfully.",
                insertedId: result.insertedId
            });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get("/getNote/:noteId", express.json(), async (req, res) => {
    try {
        const noteId = req.params.noteId;
        if (!ObjectId.isValid(noteId)) {
            return res.status(400).json({error: "Invalid note ID."});
        }

        verifyRequestAuth(req, async (err, decoded) => {
            if (err) {
              return res.status(401).send("Unauthorized.");
            }

            const collection = db.collection(COLLECTIONS.notes);
            const data = await collection.findOne({
                username: decoded.username,
                _id: new ObjectId(noteId)
            });
            if (!data) {
                return res
                    .status(404)
                    .json({error: "Unable to find note with given ID."});
            }
            res.json({ response: data });
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
