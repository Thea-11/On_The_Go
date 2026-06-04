const express = require("express");
const cors = require("cors");
const { MongoClient, ObjectId } = require("mongodb");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET = process.env.JWT_SECRET || "travelsplit-dev-secret-change-later";
const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY || "";

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static("public"));

const client = new MongoClient(process.env.MONGODB_URI);
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

let db;
let usersCollection;
let tripsCollection;
let expensesCollection;
let itineraryCollection;
let templatesCollection;
let projectsCollection;

const SUPPORTED_CURRENCIES = [
  "USD",
  "EUR",
  "GBP",
  "JPY",
  "CNY",
  "KRW",
  "CAD",
  "AUD",
  "HKD",
  "SGD",
  "THB",
  "CHF",
  "MXN",
];

function safeObjectId(id) {
  try {
    return new ObjectId(id);
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function roundMoney(value) {
  return Math.round((Number(value) || 0) * 100) / 100;
}

function normalizeCurrency(value, fallback = "USD") {
  const currency = String(value || fallback).trim().toUpperCase();
  return SUPPORTED_CURRENCIES.includes(currency) ? currency : fallback;
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function createShareToken() {
  return crypto.randomBytes(24).toString("hex");
}

function extractJson(text) {
  if (!text) return null;

  let cleaned = text.trim();

  cleaned = cleaned
    .replace(/^```json/i, "")
    .replace(/^```/i, "")
    .replace(/```$/i, "")
    .trim();

  try {
    return JSON.parse(cleaned);
  } catch {}

  const firstBrace = cleaned.indexOf("{");
  const lastBrace = cleaned.lastIndexOf("}");

  if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
    try {
      return JSON.parse(cleaned.slice(firstBrace, lastBrace + 1));
    } catch {}
  }

  return null;
}

function normalizeArray(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  return [value];
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
      name: user.name,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

async function authRequired(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : "";

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Missing token. Please log in first.",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const objectId = safeObjectId(decoded.userId);

    if (!objectId) {
      return res.status(401).json({
        success: false,
        message: "Invalid token.",
      });
    }

    const user = await usersCollection.findOne(
      { _id: objectId },
      { projection: { passwordHash: 0 } }
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found.",
      });
    }

    req.user = user;
    req.userId = user._id.toString();
    req.userEmail = normalizeEmail(user.email);

    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token.",
    });
  }
}

function getUserRoleForTrip(trip, user) {
  if (!trip || !user) return "none";

  const userId = user._id.toString();
  const email = normalizeEmail(user.email);

  if (trip.userId === userId || trip.ownerUserId === userId) {
    return "owner";
  }

  const collaborators = Array.isArray(trip.collaborators)
    ? trip.collaborators
    : [];

  const collaborator = collaborators.find(
    (item) => normalizeEmail(item.email) === email
  );

  if (collaborator) {
    return collaborator.role || "editor";
  }

  return "none";
}

function canAccessTrip(trip, user) {
  const role = getUserRoleForTrip(trip, user);
  return role === "owner" || role === "editor" || role === "viewer";
}

function canEditTrip(trip, user) {
  const role = getUserRoleForTrip(trip, user);
  return role === "owner" || role === "editor";
}

function isTripOwner(trip, user) {
  return getUserRoleForTrip(trip, user) === "owner";
}

function accessibleTripQuery(user, extra = {}) {
  const userId = user._id.toString();
  const email = normalizeEmail(user.email);

  return {
    ...extra,
    $or: [
      { userId },
      { ownerUserId: userId },
      { "collaborators.email": email },
    ],
  };
}

async function getAccessibleTripOr404(req, res, tripId) {
  const objectId = safeObjectId(tripId);

  if (!objectId) {
    res.status(400).json({
      success: false,
      message: "Invalid trip ID.",
    });
    return null;
  }

  const trip = await tripsCollection.findOne({ _id: objectId });

  if (!trip) {
    res.status(404).json({
      success: false,
      message: "Trip not found.",
    });
    return null;
  }

  if (!canAccessTrip(trip, req.user)) {
    res.status(403).json({
      success: false,
      message: "You do not have access to this trip.",
    });
    return null;
  }

  return trip;
}

async function getEditableTripOr403(req, res, tripId) {
  const trip = await getAccessibleTripOr404(req, res, tripId);
  if (!trip) return null;

  if (!canEditTrip(trip, req.user)) {
    res.status(403).json({
      success: false,
      message: "You only have view access to this trip.",
    });
    return null;
  }

  return trip;
}

async function getOwnerTripOr403(req, res, tripId) {
  const trip = await getAccessibleTripOr404(req, res, tripId);
  if (!trip) return null;

  if (!isTripOwner(trip, req.user)) {
    res.status(403).json({
      success: false,
      message: "Only the trip owner can do this.",
    });
    return null;
  }

  return trip;
}

async function convertCurrency(amount, from, to) {
  const numericAmount = Number(amount) || 0;
  const fromCurrency = normalizeCurrency(from);
  const toCurrency = normalizeCurrency(to);

  if (numericAmount === 0) {
    return {
      amount: 0,
      from: fromCurrency,
      to: toCurrency,
      convertedAmount: 0,
      exchangeRate: 1,
      rateDate: new Date().toISOString().slice(0, 10),
      provider: "none",
    };
  }

  if (fromCurrency === toCurrency) {
    return {
      amount: numericAmount,
      from: fromCurrency,
      to: toCurrency,
      convertedAmount: roundMoney(numericAmount),
      exchangeRate: 1,
      rateDate: new Date().toISOString().slice(0, 10),
      provider: "same-currency",
    };
  }

  const url = `https://api.frankfurter.app/latest?amount=${encodeURIComponent(
    numericAmount
  )}&from=${encodeURIComponent(fromCurrency)}&to=${encodeURIComponent(
    toCurrency
  )}`;

  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Exchange rate API failed: ${response.status}`);
  }

  const data = await response.json();
  const convertedAmount = Number(data.rates?.[toCurrency]);

  if (!convertedAmount && convertedAmount !== 0) {
    throw new Error(`Exchange rate not found for ${fromCurrency} to ${toCurrency}`);
  }

  return {
    amount: numericAmount,
    from: fromCurrency,
    to: toCurrency,
    convertedAmount: roundMoney(convertedAmount),
    exchangeRate: convertedAmount / numericAmount,
    rateDate: data.date || new Date().toISOString().slice(0, 10),
    provider: "Frankfurter",
  };
}

/* =========================
   GOOGLE PLACES
========================= */

function normalizePriceLevel(value) {
  if (!value) return "";
  return String(value).replace("PRICE_LEVEL_", "").replaceAll("_", " ");
}

function buildPlaceSearchQuery(activity, destination) {
  const recommendedPlace = activity.recommendedPlace || {};

  const candidates = [
    recommendedPlace.searchQuery,
    recommendedPlace.mapSearchQuery,
    activity.mapSearchQuery,
    recommendedPlace.placeName,
    activity.placeName,
    activity.location,
    activity.activity,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);

  let base = candidates[0] || "";

  if (!base) return "";

  const dest = String(destination || "").trim();

  if (dest && !base.toLowerCase().includes(dest.toLowerCase())) {
    base = `${base}, ${dest}`;
  }

  return base;
}

async function searchGooglePlace(textQuery) {
  if (!GOOGLE_PLACES_API_KEY) {
    return null;
  }

  const query = String(textQuery || "").trim();

  if (!query) {
    return null;
  }

  const response = await fetch("https://places.googleapis.com/v1/places:searchText", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY,
      "X-Goog-FieldMask":
        "places.id,places.displayName,places.formattedAddress,places.rating,places.userRatingCount,places.priceLevel,places.googleMapsUri,places.websiteUri,places.types",
    },
    body: JSON.stringify({
      textQuery: query,
      maxResultCount: 1,
      languageCode: "en",
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Google Places API failed: ${response.status} ${errorText}`);
  }

  const data = await response.json();
  const place = data.places?.[0];

  if (!place) {
    return null;
  }

  return {
    placeId: place.id || "",
    placeName: place.displayName?.text || "",
    placeAddress: place.formattedAddress || "",
    placeRating:
      place.rating !== undefined && place.rating !== null
        ? Number(place.rating)
        : "",
    placeUserRatingCount:
      place.userRatingCount !== undefined && place.userRatingCount !== null
        ? Number(place.userRatingCount)
        : "",
    placePriceLevel: normalizePriceLevel(place.priceLevel || ""),
    placeGoogleMapsUri: place.googleMapsUri || "",
    placeWebsiteUri: place.websiteUri || "",
    placeTypes: Array.isArray(place.types) ? place.types : [],
    placeDataSource: "Google Places API",
    placeFetchedAt: new Date(),
  };
}

async function enrichTravelPlanWithPlaces(travelPlan, destination) {
  if (!travelPlan || !Array.isArray(travelPlan.dailyItinerary)) {
    return travelPlan;
  }

  if (!GOOGLE_PLACES_API_KEY) {
    console.warn("GOOGLE_PLACES_API_KEY is missing. Skipping real place enrichment.");
    return travelPlan;
  }

  for (const dayBlock of travelPlan.dailyItinerary) {
    const activities = normalizeArray(dayBlock.activities);

    for (const activity of activities) {
      const searchQuery = buildPlaceSearchQuery(activity, destination || travelPlan.destination);

      activity.placeSearchQuery = searchQuery;

      if (!searchQuery) continue;

      try {
        const realPlace = await searchGooglePlace(searchQuery);

        if (realPlace) {
          activity.realPlace = realPlace;
        }
      } catch (error) {
        console.error("Google Places enrichment failed:", error.message);
        activity.realPlaceError = error.message;
      }
    }
  }

  return travelPlan;
}

function getPlaceFieldsFromActivity(activity) {
  const recommendedPlace = activity.recommendedPlace || {};
  const realPlace = activity.realPlace || {};

  return {
    placeSearchQuery:
      activity.placeSearchQuery ||
      recommendedPlace.searchQuery ||
      recommendedPlace.mapSearchQuery ||
      activity.mapSearchQuery ||
      "",
    placeId: realPlace.placeId || activity.placeId || "",
    placeName:
      realPlace.placeName ||
      recommendedPlace.placeName ||
      activity.placeName ||
      "",
    placeAddress:
      realPlace.placeAddress ||
      recommendedPlace.address ||
      activity.placeAddress ||
      "",
    placeRating:
      realPlace.placeRating !== undefined && realPlace.placeRating !== null
        ? realPlace.placeRating
        : activity.placeRating || "",
    placeUserRatingCount:
      realPlace.placeUserRatingCount !== undefined &&
      realPlace.placeUserRatingCount !== null
        ? realPlace.placeUserRatingCount
        : activity.placeUserRatingCount || "",
    placePriceLevel:
      realPlace.placePriceLevel ||
      recommendedPlace.priceLevel ||
      activity.placePriceLevel ||
      "",
    placeGoogleMapsUri:
      realPlace.placeGoogleMapsUri ||
      recommendedPlace.googleMapsUri ||
      activity.placeGoogleMapsUri ||
      "",
    placeWebsiteUri:
      realPlace.placeWebsiteUri ||
      recommendedPlace.websiteUri ||
      activity.placeWebsiteUri ||
      "",
    placeTypes:
      realPlace.placeTypes ||
      recommendedPlace.placeTypes ||
      activity.placeTypes ||
      [],
    placeDataSource:
      realPlace.placeDataSource ||
      activity.placeDataSource ||
      "",
    placeFetchedAt:
      realPlace.placeFetchedAt ||
      activity.placeFetchedAt ||
      null,
  };
}

/* =========================
   AI TRIP GENERATION
========================= */

function createFlightContext(data) {
  const mode = data.flightMode || "estimated";

  if (mode === "confirmed") {
    return `
The user already purchased flight tickets.

Known information:
- Flight number: ${data.flightNumber || "Not provided"}
- Flight date: ${data.flightDate || "Not provided"}
- Origin city or airport: ${data.origin || "Not provided"}
- Destination: ${data.destination || "Not provided"}
- Hotel or stay area: ${data.hotelArea || "Not provided"}
- Optional actual arrival date: ${data.arrivalDate || "Not provided"}
- Optional actual arrival time: ${data.arrivalTime || "Not provided"}
- Optional return departure date: ${data.returnDepartureDate || "Not provided"}
- Optional return departure time: ${data.returnDepartureTime || "Not provided"}

Important rules:
1. The user may only know the flight number and flight date.
2. Do not require exact arrival time.
3. If exact arrival time is missing, make Day 1 flexible and light.
4. Include a reminder that the user should confirm actual arrival time later.
5. If hotel or stay area is provided, use it as the route base.
6. If hotel area is missing, suggest a convenient stay area.
7. The daily itinerary should still be useful even without real-time flight API data.
`;
  }

  return `
The user has not purchased flights yet.

Known information:
- Destination: ${data.destination || "Not provided"}
- Estimated start date: ${data.startDate || "Not provided"}
- Trip length: ${data.tripDays || data.days || "Not provided"} days
- Origin city: ${data.origin || "Not provided"}
- Hotel or stay area: ${data.hotelArea || "Not provided"}

Important rules:
1. Since the user has not bought tickets, create a flexible itinerary.
2. Day 1 should include arrival/check-in flexibility.
3. The last day should stay lighter for possible departure.
4. If hotel or stay area is provided, use it as the route base.
5. If hotel area is missing, recommend a good area to stay.
`;
}

async function generateTripWithAI(data) {
  const model = genAI.getGenerativeModel({
    model: "gemini-2.5-flash-lite",
    generationConfig: {
      responseMimeType: "application/json",
    },
  });

  const flightContext = createFlightContext(data);

  const prompt = `
You are TravelSplit AI, an intelligent travel planning and group expense assistant.

Create a detailed travel plan in valid JSON only.

${flightContext}

User note:
${data.prompt || "No extra note."}

Optional advanced preferences:
- Travelers: ${data.travelers || "Not provided"}
- Budget level: ${data.budget || "medium"}
- Travel style: ${data.travelStyle || "balanced"}
- Food preference: ${data.foodPreference || "local food"}
- Pace: ${data.pace || "medium"}
- Must-see places: ${data.mustSee || "not provided"}
- Avoid: ${data.avoid || "not provided"}

Important place recommendation rules:
1. Every activity should include a realistic recommended place, not only restaurants.
2. For attractions, cafes, restaurants, shopping, museums, parks, markets, and experiences, include a Google-searchable place query.
3. Do not invent fake exact ratings. Real ratings will be fetched later by Google Places API.
4. For each activity, create "recommendedPlace.searchQuery" that is specific enough for Google Places Text Search.
5. The search query should include the place name or activity type plus neighborhood/city.
6. If you are unsure of the exact place, use a high-quality searchable query such as "best ramen restaurant in Shinjuku Tokyo".

Return ONLY valid JSON in this exact structure:

{
  "tripTitle": "",
  "destination": "",
  "summary": "",
  "flightMode": "confirmed or estimated",
  "flightPlan": {
    "status": "",
    "explanation": "",
    "arrivalStrategy": "",
    "departureStrategy": "",
    "airportTransferTips": []
  },
  "destinationAnalysis": {
    "bestAreasToStay": [],
    "travelStyleFit": "",
    "weatherNotes": "",
    "localTips": []
  },
  "dailyItinerary": [
    {
      "day": 1,
      "date": "",
      "theme": "",
      "flightImpact": "",
      "activities": [
        {
          "startTime": "",
          "endTime": "",
          "activity": "",
          "location": "",
          "transport": "",
          "estimatedTravelTime": "",
          "notes": "",
          "recommendedPlace": {
            "placeName": "",
            "placeType": "restaurant | cafe | attraction | museum | shopping | park | market | experience | transport | other",
            "searchQuery": "",
            "whyRecommended": "",
            "signatureItem": ""
          }
        }
      ]
    }
  ],
  "budgetAdvice": {
    "estimatedTotal": "",
    "dailyBudget": "",
    "savingTips": []
  },
  "transitLogistics": {
    "mainTransport": "",
    "tips": []
  },
  "foodLocalExperiences": {
    "recommendedFoods": [],
    "restaurantIdeas": [],
    "localExperiences": []
  },
  "safetyRiskAlerts": {
    "generalSafety": "",
    "commonRisks": [],
    "emergencyTips": []
  },
  "packingChecklist": [],
  "nextSteps": []
}

Daily itinerary requirements:
- Include realistic times.
- Include transportation between places.
- Include estimated travel time.
- Include meals or food ideas when useful.
- If exact flight time is missing, avoid pretending to know exact arrival time.
- If hotel or stay area is provided, design routes around that area.
- Every activity must include recommendedPlace.searchQuery.
`;

  const result = await model.generateContent(prompt);
  const text = result.response.text();
  const parsed = extractJson(text);

  if (!parsed) {
    throw new Error("Gemini did not return valid JSON.");
  }

  await enrichTravelPlanWithPlaces(parsed, data.destination || parsed.destination || "");

  return {
    parsed,
    raw: text,
  };
}

async function saveGeneratedItinerary(tripId, travelPlan, ownerUserId, createdByUserId) {
  if (!travelPlan || !Array.isArray(travelPlan.dailyItinerary)) return;

  const tripIdString = tripId.toString();

  await itineraryCollection.deleteMany({
    tripId: tripIdString,
  });

  const items = [];

  travelPlan.dailyItinerary.forEach((dayBlock) => {
    const day = Number(dayBlock.day) || 1;
    const date = dayBlock.date || "";
    const activities = normalizeArray(dayBlock.activities);

    activities.forEach((activity, index) => {
      const recommendedPlace = activity.recommendedPlace || {};
      const placeFields = getPlaceFieldsFromActivity(activity);

      items.push({
        ownerUserId,
        createdByUserId: createdByUserId || ownerUserId,
        userId: ownerUserId,
        tripId: tripIdString,
        day,
        date,
        order: index + 1,
        startTime: activity.startTime || "",
        endTime: activity.endTime || "",
        activity: activity.activity || "Untitled Activity",
        location: activity.location || "",
        transport: activity.transport || "",
        estimatedTravelTime: activity.estimatedTravelTime || "",
        notes: activity.notes || "",

        placeName: placeFields.placeName,
        placeType: recommendedPlace.placeType || activity.placeType || "",
        placeSearchQuery: placeFields.placeSearchQuery,
        placeAddress: placeFields.placeAddress,
        placeRating: placeFields.placeRating,
        placeUserRatingCount: placeFields.placeUserRatingCount,
        placePriceLevel: placeFields.placePriceLevel,
        placeGoogleMapsUri: placeFields.placeGoogleMapsUri,
        placeWebsiteUri: placeFields.placeWebsiteUri,
        placeTypes: placeFields.placeTypes,
        placeId: placeFields.placeId,
        placeDataSource: placeFields.placeDataSource,
        placeFetchedAt: placeFields.placeFetchedAt,
        whyRecommended:
          recommendedPlace.whyRecommended ||
          activity.whyRecommended ||
          "",
        signatureItem:
          recommendedPlace.signatureItem ||
          activity.signatureItem ||
          "",

        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });
  });

  if (items.length > 0) {
    await itineraryCollection.insertMany(items);
  }
}

async function createTripHandler(req, res) {
  try {
    const data = req.body || {};
    const userId = req.userId;

    if (!data.destination && !data.prompt) {
      return res.status(400).json({
        success: false,
        message: "Destination or prompt is required.",
      });
    }

    const aiResult = await generateTripWithAI(data);
    const travelPlan = aiResult.parsed;

    const tripDoc = {
      userId,
      ownerUserId: userId,
      ownerEmail: req.userEmail,
      ownerName: req.user.name || "",
      title:
        travelPlan.tripTitle ||
        `${data.destination || "Untitled Trip"} Travel Plan`,
      destination: travelPlan.destination || data.destination || "",
      prompt: data.prompt || "",
      flightMode: data.flightMode || travelPlan.flightMode || "estimated",
      flightInfo: {
        flightNumber: data.flightNumber || "",
        flightDate: data.flightDate || "",
        origin: data.origin || "",
        destination: data.destination || "",
        hotelArea: data.hotelArea || "",
        arrivalDate: data.arrivalDate || "",
        arrivalTime: data.arrivalTime || "",
        returnDepartureDate: data.returnDepartureDate || "",
        returnDepartureTime: data.returnDepartureTime || "",
        startDate: data.startDate || "",
        tripDays: data.tripDays || data.days || "",
      },
      travelPlan,
      rawReply: aiResult.raw,
      pinned: false,
      archived: false,
      projectId: "",
      projectName: "",
      collaborators: [],
      publicShareEnabled: false,
      shareToken: "",
      shareCreatedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const insertResult = await tripsCollection.insertOne(tripDoc);
    const tripId = insertResult.insertedId;

    await saveGeneratedItinerary(tripId, travelPlan, userId, userId);

    res.json({
      success: true,
      tripId: tripId.toString(),
      trip: {
        ...tripDoc,
        _id: tripId,
        currentUserRole: "owner",
      },
      travelPlan,
    });
  } catch (error) {
    console.error("Error generating trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate trip.",
      error: error.message,
    });
  }
}

/* =========================
   AUTH ROUTES
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email, and password are required.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters.",
      });
    }

    const existing = await usersCollection.findOne({ email });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "This email is already registered.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const userDoc = {
      name,
      email,
      passwordHash,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await usersCollection.insertOne(userDoc);

    const user = {
      _id: result.insertedId,
      name,
      email,
    };

    const token = createToken(user);

    res.json({
      success: true,
      token,
      user,
    });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to register.",
      error: error.message,
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required.",
      });
    }

    const userDoc = await usersCollection.findOne({ email });

    if (!userDoc) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const passwordOk = await bcrypt.compare(password, userDoc.passwordHash);

    if (!passwordOk) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password.",
      });
    }

    const user = {
      _id: userDoc._id,
      name: userDoc.name,
      email: userDoc.email,
    };

    const token = createToken(user);

    res.json({
      success: true,
      token,
      user,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to login.",
      error: error.message,
    });
  }
});

app.get("/api/auth/me", authRequired, async (req, res) => {
  res.json({
    success: true,
    user: {
      _id: req.user._id,
      name: req.user.name,
      email: req.user.email,
    },
  });
});

/* =========================
   APP BASIC ROUTES
========================= */

app.get("/api/currencies", authRequired, (req, res) => {
  res.json({
    success: true,
    currencies: SUPPORTED_CURRENCIES,
  });
});

app.get("/api/exchange-rate", authRequired, async (req, res) => {
  try {
    const amount = Number(req.query.amount) || 1;
    const from = normalizeCurrency(req.query.from || "USD");
    const to = normalizeCurrency(req.query.to || "USD");

    const result = await convertCurrency(amount, from, to);

    res.json({
      success: true,
      ...result,
    });
  } catch (error) {
    console.error("Error converting currency:", error);
    res.status(500).json({
      success: false,
      message: "Failed to convert currency.",
      error: error.message,
    });
  }
});

app.get("/api/places/search", authRequired, async (req, res) => {
  try {
    const query = String(req.query.query || "").trim();

    if (!query) {
      return res.status(400).json({
        success: false,
        message: "Query is required.",
      });
    }

    const place = await searchGooglePlace(query);

    res.json({
      success: true,
      query,
      place,
    });
  } catch (error) {
    console.error("Error searching Google Places:", error);
    res.status(500).json({
      success: false,
      message: "Failed to search Google Places.",
      error: error.message,
    });
  }
});

app.post("/api/generate-trip", authRequired, createTripHandler);
app.post("/api/trips/generate", authRequired, createTripHandler);

/* =========================
   PROJECT ROUTES
========================= */

app.get("/api/projects", authRequired, async (req, res) => {
  try {
    const projects = await projectsCollection
      .find({ userId: req.userId })
      .sort({ updatedAt: -1, createdAt: -1 })
      .toArray();

    const projectIds = projects.map((project) => project._id.toString());

    const tripCounts = await tripsCollection
      .aggregate([
        {
          $match: {
            userId: req.userId,
            archived: { $ne: true },
            projectId: { $in: projectIds },
          },
        },
        {
          $group: {
            _id: "$projectId",
            count: { $sum: 1 },
          },
        },
      ])
      .toArray();

    const countMap = {};

    tripCounts.forEach((item) => {
      countMap[item._id] = item.count;
    });

    res.json({
      success: true,
      projects: projects.map((project) => ({
        ...project,
        tripCount: countMap[project._id.toString()] || 0,
      })),
    });
  } catch (error) {
    console.error("Error fetching projects:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch projects.",
    });
  }
});

app.post("/api/projects", authRequired, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Project name is required.",
      });
    }

    const existing = await projectsCollection.findOne({
      userId: req.userId,
      name,
    });

    if (existing) {
      return res.status(409).json({
        success: false,
        message: "A project with this name already exists.",
      });
    }

    const projectDoc = {
      userId: req.userId,
      ownerUserId: req.userId,
      name,
      description,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await projectsCollection.insertOne(projectDoc);

    res.json({
      success: true,
      project: {
        ...projectDoc,
        _id: result.insertedId,
        tripCount: 0,
      },
    });
  } catch (error) {
    console.error("Error creating project:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create project.",
    });
  }
});

app.put("/api/projects/:projectId/rename", authRequired, async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.projectId);
    const name = String(req.body.name || "").trim();
    const description = String(req.body.description || "").trim();

    if (!objectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid project ID.",
      });
    }

    if (!name) {
      return res.status(400).json({
        success: false,
        message: "Project name is required.",
      });
    }

    const project = await projectsCollection.findOne({
      _id: objectId,
      userId: req.userId,
    });

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project not found.",
      });
    }

    await projectsCollection.updateOne(
      { _id: objectId, userId: req.userId },
      {
        $set: {
          name,
          description,
          updatedAt: new Date(),
        },
      }
    );

    await tripsCollection.updateMany(
      {
        userId: req.userId,
        projectId: req.params.projectId,
      },
      {
        $set: {
          projectName: name,
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Project updated.",
    });
  } catch (error) {
    console.error("Error renaming project:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update project.",
    });
  }
});

app.delete("/api/projects/:projectId", authRequired, async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.projectId);

    if (!objectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid project ID.",
      });
    }

    const project = await projectsCollection.findOne({
      _id: objectId,
      userId: req.userId,
    });

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project not found.",
      });
    }

    await tripsCollection.updateMany(
      {
        userId: req.userId,
        projectId: req.params.projectId,
      },
      {
        $set: {
          projectId: "",
          projectName: "",
          updatedAt: new Date(),
        },
      }
    );

    await projectsCollection.deleteOne({
      _id: objectId,
      userId: req.userId,
    });

    res.json({
      success: true,
      message: "Project deleted. Trips were moved back to Recent.",
    });
  } catch (error) {
    console.error("Error deleting project:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete project.",
    });
  }
});

app.get("/api/projects/:projectId/trips", authRequired, async (req, res) => {
  try {
    const projectObjectId = safeObjectId(req.params.projectId);

    if (!projectObjectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid project ID.",
      });
    }

    const project = await projectsCollection.findOne({
      _id: projectObjectId,
      userId: req.userId,
    });

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project not found.",
      });
    }

    const trips = await tripsCollection
      .find({
        userId: req.userId,
        projectId: req.params.projectId,
        archived: { $ne: true },
      })
      .sort({ pinned: -1, updatedAt: -1, createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      project,
      trips: trips.map((trip) => ({
        ...trip,
        currentUserRole: "owner",
        isSharedWithMe: false,
      })),
    });
  } catch (error) {
    console.error("Error fetching project trips:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch project trips.",
    });
  }
});

app.put("/api/trips/:tripId/move-to-project", authRequired, async (req, res) => {
  try {
    const tripObjectId = safeObjectId(req.params.tripId);
    const projectId = String(req.body.projectId || "").trim();

    if (!tripObjectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid trip ID.",
      });
    }

    if (!projectId) {
      return res.status(400).json({
        success: false,
        message: "Project ID is required.",
      });
    }

    const projectObjectId = safeObjectId(projectId);

    if (!projectObjectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid project ID.",
      });
    }

    const trip = await tripsCollection.findOne({
      _id: tripObjectId,
      userId: req.userId,
    });

    if (!trip) {
      return res.status(404).json({
        success: false,
        message: "Trip not found or you are not the owner.",
      });
    }

    const project = await projectsCollection.findOne({
      _id: projectObjectId,
      userId: req.userId,
    });

    if (!project) {
      return res.status(404).json({
        success: false,
        message: "Project not found.",
      });
    }

    await tripsCollection.updateOne(
      {
        _id: tripObjectId,
        userId: req.userId,
      },
      {
        $set: {
          projectId: project._id.toString(),
          projectName: project.name,
          updatedAt: new Date(),
        },
      }
    );

    await projectsCollection.updateOne(
      {
        _id: projectObjectId,
        userId: req.userId,
      },
      {
        $set: {
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Trip moved to project.",
      projectId: project._id.toString(),
      projectName: project.name,
    });
  } catch (error) {
    console.error("Error moving trip to project:", error);
    res.status(500).json({
      success: false,
      message: "Failed to move trip to project.",
    });
  }
});

app.put("/api/trips/:tripId/remove-from-project", authRequired, async (req, res) => {
  try {
    const tripObjectId = safeObjectId(req.params.tripId);

    if (!tripObjectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid trip ID.",
      });
    }

    const trip = await tripsCollection.findOne({
      _id: tripObjectId,
      userId: req.userId,
    });

    if (!trip) {
      return res.status(404).json({
        success: false,
        message: "Trip not found or you are not the owner.",
      });
    }

    await tripsCollection.updateOne(
      {
        _id: tripObjectId,
        userId: req.userId,
      },
      {
        $set: {
          projectId: "",
          projectName: "",
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Trip removed from project.",
    });
  } catch (error) {
    console.error("Error removing trip from project:", error);
    res.status(500).json({
      success: false,
      message: "Failed to remove trip from project.",
    });
  }
});

/* =========================
   TRIPS LIST ROUTES
========================= */

app.get("/api/trips/archived", authRequired, async (req, res) => {
  try {
    const trips = await tripsCollection
      .find(accessibleTripQuery(req.user, { archived: true }))
      .sort({ updatedAt: -1, createdAt: -1 })
      .limit(50)
      .toArray();

    res.json({
      success: true,
      trips: trips.map((trip) => ({
        ...trip,
        currentUserRole: getUserRoleForTrip(trip, req.user),
        isSharedWithMe: trip.userId !== req.userId && trip.ownerUserId !== req.userId,
      })),
    });
  } catch (error) {
    console.error("Error fetching archived trips:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch archived trips.",
    });
  }
});

app.get("/api/trips/shared", authRequired, async (req, res) => {
  try {
    const trips = await tripsCollection
      .find({
        "collaborators.email": req.userEmail,
        archived: { $ne: true },
      })
      .sort({ updatedAt: -1, createdAt: -1 })
      .limit(50)
      .toArray();

    res.json({
      success: true,
      trips: trips.map((trip) => ({
        ...trip,
        currentUserRole: getUserRoleForTrip(trip, req.user),
        isSharedWithMe: true,
      })),
    });
  } catch (error) {
    console.error("Error fetching shared trips:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch shared trips.",
    });
  }
});

app.get("/api/trips", authRequired, async (req, res) => {
  try {
    const trips = await tripsCollection
      .find(
        accessibleTripQuery(req.user, {
          archived: { $ne: true },
          $and: [
            {
              $or: [
                { projectId: { $exists: false } },
                { projectId: "" },
                { projectId: null },
                { "collaborators.email": req.userEmail },
              ],
            },
          ],
        })
      )
      .sort({ pinned: -1, updatedAt: -1, createdAt: -1 })
      .limit(50)
      .toArray();

    res.json({
      success: true,
      trips: trips.map((trip) => ({
        ...trip,
        currentUserRole: getUserRoleForTrip(trip, req.user),
        isSharedWithMe: trip.userId !== req.userId && trip.ownerUserId !== req.userId,
      })),
    });
  } catch (error) {
    console.error("Error fetching trips:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch trips.",
    });
  }
});

app.get("/api/trips/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getAccessibleTripOr404(req, res, req.params.tripId);
    if (!trip) return;

    res.json({
      success: true,
      trip: {
        ...trip,
        currentUserRole: getUserRoleForTrip(trip, req.user),
        isSharedWithMe: trip.userId !== req.userId && trip.ownerUserId !== req.userId,
      },
    });
  } catch (error) {
    console.error("Error fetching trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch trip.",
    });
  }
});

/* =========================
   SHARE / COLLABORATORS / ARCHIVE
========================= */

app.put("/api/trips/:tripId/archive", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          archived: true,
          archivedAt: new Date(),
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Trip archived.",
    });
  } catch (error) {
    console.error("Error archiving trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to archive trip.",
    });
  }
});

app.put("/api/trips/:tripId/restore", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          archived: false,
          updatedAt: new Date(),
        },
        $unset: {
          archivedAt: "",
        },
      }
    );

    res.json({
      success: true,
      message: "Trip restored.",
    });
  } catch (error) {
    console.error("Error restoring trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to restore trip.",
    });
  }
});

app.post("/api/trips/:tripId/share", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    const shareToken = trip.shareToken || createShareToken();

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          publicShareEnabled: true,
          shareToken,
          shareCreatedAt: trip.shareCreatedAt || new Date(),
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      shareToken,
      shareUrl: `${req.protocol}://${req.get("host")}/share-trip/${shareToken}`,
      publicApiUrl: `${req.protocol}://${req.get("host")}/api/public/share/${shareToken}`,
    });
  } catch (error) {
    console.error("Error creating share link:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create share link.",
    });
  }
});

app.delete("/api/trips/:tripId/share", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          publicShareEnabled: false,
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Share link disabled.",
    });
  } catch (error) {
    console.error("Error disabling share link:", error);
    res.status(500).json({
      success: false,
      message: "Failed to disable share link.",
    });
  }
});

app.get("/api/trips/:tripId/collaborators", authRequired, async (req, res) => {
  try {
    const trip = await getAccessibleTripOr404(req, res, req.params.tripId);
    if (!trip) return;

    res.json({
      success: true,
      owner: {
        userId: trip.userId || trip.ownerUserId,
        name: trip.ownerName || "Owner",
        email: trip.ownerEmail || "",
      },
      currentUserRole: getUserRoleForTrip(trip, req.user),
      collaborators: Array.isArray(trip.collaborators) ? trip.collaborators : [],
    });
  } catch (error) {
    console.error("Error fetching collaborators:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch collaborators.",
    });
  }
});

app.post("/api/trips/:tripId/collaborators", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    const email = normalizeEmail(req.body.email);
    const role = req.body.role === "viewer" ? "viewer" : "editor";

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Collaborator email is required.",
      });
    }

    if (email === req.userEmail) {
      return res.status(400).json({
        success: false,
        message: "You are already the owner of this trip.",
      });
    }

    const invitedUser = await usersCollection.findOne(
      { email },
      { projection: { passwordHash: 0 } }
    );

    const existingCollaborators = Array.isArray(trip.collaborators)
      ? trip.collaborators
      : [];

    const alreadyExists = existingCollaborators.some(
      (item) => normalizeEmail(item.email) === email
    );

    if (alreadyExists) {
      await tripsCollection.updateOne(
        {
          _id: trip._id,
          "collaborators.email": email,
        },
        {
          $set: {
            "collaborators.$.role": role,
            "collaborators.$.status": invitedUser ? "active" : "invited",
            "collaborators.$.userId": invitedUser ? invitedUser._id.toString() : "",
            "collaborators.$.name": invitedUser ? invitedUser.name || "" : "",
            "collaborators.$.updatedAt": new Date(),
            updatedAt: new Date(),
          },
        }
      );
    } else {
      await tripsCollection.updateOne(
        { _id: trip._id },
        {
          $push: {
            collaborators: {
              email,
              userId: invitedUser ? invitedUser._id.toString() : "",
              name: invitedUser ? invitedUser.name || "" : "",
              role,
              status: invitedUser ? "active" : "invited",
              invitedByUserId: req.userId,
              invitedByEmail: req.userEmail,
              invitedAt: new Date(),
              updatedAt: new Date(),
            },
          },
          $set: {
            updatedAt: new Date(),
          },
        }
      );
    }

    const updatedTrip = await tripsCollection.findOne({ _id: trip._id });

    res.json({
      success: true,
      message: invitedUser
        ? "Collaborator added."
        : "Collaborator invited. They will see the trip after registering with this email.",
      collaborators: updatedTrip.collaborators || [],
    });
  } catch (error) {
    console.error("Error adding collaborator:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add collaborator.",
    });
  }
});

app.delete("/api/trips/:tripId/collaborators/:email", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    const email = normalizeEmail(req.params.email);

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $pull: {
          collaborators: { email },
        },
        $set: {
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Collaborator removed.",
    });
  } catch (error) {
    console.error("Error removing collaborator:", error);
    res.status(500).json({
      success: false,
      message: "Failed to remove collaborator.",
    });
  }
});

/* =========================
   TRIP CRUD
========================= */

app.put("/api/trips/:tripId/rename", authRequired, async (req, res) => {
  try {
    const trip = await getEditableTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    const title = String(req.body.title || "").trim();

    if (!title) {
      return res.status(400).json({
        success: false,
        message: "Title is required.",
      });
    }

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          title,
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: "Trip renamed.",
    });
  } catch (error) {
    console.error("Error renaming trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to rename trip.",
    });
  }
});

app.put("/api/trips/:tripId/pin", authRequired, async (req, res) => {
  try {
    const trip = await getEditableTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          pinned: Boolean(req.body.pinned),
          updatedAt: new Date(),
        },
      }
    );

    res.json({
      success: true,
      message: req.body.pinned ? "Trip pinned." : "Trip unpinned.",
    });
  } catch (error) {
    console.error("Error pinning trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update pin status.",
    });
  }
});

app.delete("/api/trips/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getOwnerTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    await tripsCollection.deleteOne({ _id: trip._id });
    await itineraryCollection.deleteMany({ tripId: req.params.tripId });
    await expensesCollection.deleteMany({ tripId: req.params.tripId });

    res.json({
      success: true,
      message: "Trip deleted.",
    });
  } catch (error) {
    console.error("Error deleting trip:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete trip.",
    });
  }
});

app.post("/api/trips/:tripId/regenerate-itinerary", authRequired, async (req, res) => {
  try {
    const trip = await getEditableTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    const data = {
      ...(trip.flightInfo || {}),
      ...(req.body || {}),
      destination:
        req.body.destination ||
        trip.destination ||
        trip.flightInfo?.destination ||
        "",
      prompt:
        req.body.prompt ||
        trip.prompt ||
        `Regenerate a detailed daily itinerary for ${trip.destination}.`,
      flightMode: req.body.flightMode || trip.flightMode || "estimated",
    };

    const aiResult = await generateTripWithAI(data);
    const travelPlan = aiResult.parsed;

    await tripsCollection.updateOne(
      { _id: trip._id },
      {
        $set: {
          travelPlan,
          rawReply: aiResult.raw,
          flightMode: data.flightMode,
          flightInfo: {
            flightNumber: data.flightNumber || "",
            flightDate: data.flightDate || "",
            origin: data.origin || "",
            destination: data.destination || "",
            hotelArea: data.hotelArea || "",
            arrivalDate: data.arrivalDate || "",
            arrivalTime: data.arrivalTime || "",
            returnDepartureDate: data.returnDepartureDate || "",
            returnDepartureTime: data.returnDepartureTime || "",
            startDate: data.startDate || "",
            tripDays: data.tripDays || data.days || "",
          },
          updatedAt: new Date(),
        },
      }
    );

    await saveGeneratedItinerary(
      req.params.tripId,
      travelPlan,
      trip.userId || trip.ownerUserId,
      req.userId
    );

    res.json({
      success: true,
      travelPlan,
    });
  } catch (error) {
    console.error("Error regenerating itinerary:", error);
    res.status(500).json({
      success: false,
      message: "Failed to regenerate itinerary.",
      error: error.message,
    });
  }
});

/* =========================
   ITINERARY ROUTES
========================= */

app.get("/api/itinerary/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getAccessibleTripOr404(req, res, req.params.tripId);
    if (!trip) return;

    const items = await itineraryCollection
      .find({ tripId: req.params.tripId })
      .sort({ day: 1, order: 1, startTime: 1 })
      .toArray();

    res.json({
      success: true,
      items,
      currentUserRole: getUserRoleForTrip(trip, req.user),
    });
  } catch (error) {
    console.error("Error fetching itinerary:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch itinerary.",
    });
  }
});

app.post("/api/itinerary/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getEditableTripOr403(req, res, req.params.tripId);
    if (!trip) return;

    const placeQuery =
      req.body.placeSearchQuery ||
      req.body.placeName ||
      req.body.location ||
      req.body.activity ||
      "";

    let realPlace = null;

    if (placeQuery) {
      try {
        realPlace = await searchGooglePlace(
          `${placeQuery}, ${trip.destination || trip.flightInfo?.destination || ""}`
        );
      } catch (error) {
        console.error("Manual itinerary place search failed:", error.message);
      }
    }

    const item = {
      ownerUserId: trip.userId || trip.ownerUserId,
      createdByUserId: req.userId,
      userId: trip.userId || trip.ownerUserId,
      tripId: req.params.tripId,
      day: Number(req.body.day) || 1,
      date: req.body.date || "",
      order: Number(req.body.order) || Date.now(),
      startTime: req.body.startTime || "",
      endTime: req.body.endTime || "",
      activity: req.body.activity || "Untitled Activity",
      location: req.body.location || "",
      transport: req.body.transport || "",
      estimatedTravelTime: req.body.estimatedTravelTime || "",
      notes: req.body.notes || "",

      placeName: realPlace?.placeName || req.body.placeName || "",
      placeType: req.body.placeType || "",
      placeSearchQuery: placeQuery,
      placeAddress: realPlace?.placeAddress || req.body.placeAddress || "",
      placeRating: realPlace?.placeRating || req.body.placeRating || "",
      placeUserRatingCount:
        realPlace?.placeUserRatingCount || req.body.placeUserRatingCount || "",
      placePriceLevel: realPlace?.placePriceLevel || req.body.placePriceLevel || "",
      placeGoogleMapsUri:
        realPlace?.placeGoogleMapsUri || req.body.placeGoogleMapsUri || "",
      placeWebsiteUri:
        realPlace?.placeWebsiteUri || req.body.placeWebsiteUri || "",
      placeTypes: realPlace?.placeTypes || req.body.placeTypes || [],
      placeId: realPlace?.placeId || req.body.placeId || "",
      placeDataSource: realPlace?.placeDataSource || req.body.placeDataSource || "",
      placeFetchedAt: realPlace?.placeFetchedAt || null,
      whyRecommended: req.body.whyRecommended || "",
      signatureItem: req.body.signatureItem || "",

      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await itineraryCollection.insertOne(item);

    await tripsCollection.updateOne(
      { _id: trip._id },
      { $set: { updatedAt: new Date() } }
    );

    res.json({
      success: true,
      item: {
        ...item,
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Error adding itinerary item:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add itinerary item.",
    });
  }
});

app.put("/api/itinerary/item/:itemId", authRequired, async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.itemId);

    if (!objectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid item ID.",
      });
    }

    const existingItem = await itineraryCollection.findOne({ _id: objectId });

    if (!existingItem) {
      return res.status(404).json({
        success: false,
        message: "Itinerary item not found.",
      });
    }

    const trip = await getEditableTripOr403(req, res, existingItem.tripId);
    if (!trip) return;

    const placeQuery =
      req.body.placeSearchQuery ||
      req.body.placeName ||
      req.body.location ||
      req.body.activity ||
      "";

    let realPlace = null;

    if (placeQuery) {
      try {
        realPlace = await searchGooglePlace(
          `${placeQuery}, ${trip.destination || trip.flightInfo?.destination || ""}`
        );
      } catch (error) {
        console.error("Update itinerary place search failed:", error.message);
      }
    }

    await itineraryCollection.updateOne(
      { _id: objectId },
      {
        $set: {
          day: Number(req.body.day) || 1,
          date: req.body.date || "",
          startTime: req.body.startTime || "",
          endTime: req.body.endTime || "",
          activity: req.body.activity || "Untitled Activity",
          location: req.body.location || "",
          transport: req.body.transport || "",
          estimatedTravelTime: req.body.estimatedTravelTime || "",
          notes: req.body.notes || "",

          placeName: realPlace?.placeName || req.body.placeName || "",
          placeType: req.body.placeType || "",
          placeSearchQuery: placeQuery,
          placeAddress: realPlace?.placeAddress || req.body.placeAddress || "",
          placeRating: realPlace?.placeRating || req.body.placeRating || "",
          placeUserRatingCount:
            realPlace?.placeUserRatingCount || req.body.placeUserRatingCount || "",
          placePriceLevel:
            realPlace?.placePriceLevel || req.body.placePriceLevel || "",
          placeGoogleMapsUri:
            realPlace?.placeGoogleMapsUri || req.body.placeGoogleMapsUri || "",
          placeWebsiteUri:
            realPlace?.placeWebsiteUri || req.body.placeWebsiteUri || "",
          placeTypes: realPlace?.placeTypes || req.body.placeTypes || [],
          placeId: realPlace?.placeId || req.body.placeId || "",
          placeDataSource:
            realPlace?.placeDataSource || req.body.placeDataSource || "",
          placeFetchedAt: realPlace?.placeFetchedAt || null,
          whyRecommended: req.body.whyRecommended || "",
          signatureItem: req.body.signatureItem || "",
          updatedByUserId: req.userId,
          updatedAt: new Date(),
        },
      }
    );

    await tripsCollection.updateOne(
      { _id: trip._id },
      { $set: { updatedAt: new Date() } }
    );

    res.json({
      success: true,
      message: "Itinerary item updated.",
    });
  } catch (error) {
    console.error("Error updating itinerary item:", error);
    res.status(500).json({
      success: false,
      message: "Failed to update itinerary item.",
    });
  }
});

app.delete("/api/itinerary/item/:itemId", authRequired, async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.itemId);

    if (!objectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid item ID.",
      });
    }

    const existingItem = await itineraryCollection.findOne({ _id: objectId });

    if (!existingItem) {
      return res.status(404).json({
        success: false,
        message: "Itinerary item not found.",
      });
    }

    const trip = await getEditableTripOr403(req, res, existingItem.tripId);
    if (!trip) return;

    await itineraryCollection.deleteOne({ _id: objectId });

    await tripsCollection.updateOne(
      { _id: trip._id },
      { $set: { updatedAt: new Date() } }
    );

    res.json({
      success: true,
      message: "Itinerary item deleted.",
    });
  } catch (error) {
    console.error("Error deleting itinerary item:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete itinerary item.",
    });
  }
});

/* =========================
   EXPENSE ROUTES
========================= */

app.post("/api/add-expense", authRequired, async (req, res) => {
  try {
    const trip = await getEditableTripOr403(req, res, req.body.tripId);
    if (!trip) return;

    const amount = Number(req.body.amount) || 0;
    const currency = normalizeCurrency(req.body.currency || "USD");
    const baseCurrency = normalizeCurrency(req.body.baseCurrency || "USD");

    let conversion;

    try {
      conversion = await convertCurrency(amount, currency, baseCurrency);
    } catch (conversionError) {
      console.error("Currency conversion failed. Saving original amount only:", conversionError);

      conversion = {
        amount,
        from: currency,
        to: baseCurrency,
        convertedAmount: amount,
        exchangeRate: 1,
        rateDate: new Date().toISOString().slice(0, 10),
        provider: "fallback",
      };
    }

    const expense = {
      ownerUserId: trip.userId || trip.ownerUserId,
      createdByUserId: req.userId,
      userId: trip.userId || trip.ownerUserId,
      tripId: req.body.tripId || "",
      description: req.body.description || "",
      amount,
      currency,
      baseCurrency,
      convertedAmount: conversion.convertedAmount,
      exchangeRate: conversion.exchangeRate,
      rateDate: conversion.rateDate,
      rateProvider: conversion.provider,
      paidBy: req.body.paidBy || "",
      sharedWith: Array.isArray(req.body.sharedWith)
        ? req.body.sharedWith
        : String(req.body.sharedWith || "")
            .split(",")
            .map((name) => name.trim())
            .filter(Boolean),
      category: req.body.category || "",
      date: req.body.date || "",
      location: req.body.location || "",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await expensesCollection.insertOne(expense);

    await tripsCollection.updateOne(
      { _id: trip._id },
      { $set: { updatedAt: new Date() } }
    );

    res.json({
      success: true,
      expense: {
        ...expense,
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Error adding expense:", error);
    res.status(500).json({
      success: false,
      message: "Failed to add expense.",
      error: error.message,
    });
  }
});

app.get("/api/expenses/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getAccessibleTripOr404(req, res, req.params.tripId);
    if (!trip) return;

    const expenses = await expensesCollection
      .find({ tripId: req.params.tripId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      expenses,
      currentUserRole: getUserRoleForTrip(trip, req.user),
    });
  } catch (error) {
    console.error("Error fetching expenses:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch expenses.",
    });
  }
});

app.delete("/api/expenses/:expenseId", authRequired, async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.expenseId);

    if (!objectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid expense ID.",
      });
    }

    const expense = await expensesCollection.findOne({ _id: objectId });

    if (!expense) {
      return res.status(404).json({
        success: false,
        message: "Expense not found.",
      });
    }

    const trip = await getEditableTripOr403(req, res, expense.tripId);
    if (!trip) return;

    await expensesCollection.deleteOne({ _id: objectId });

    await tripsCollection.updateOne(
      { _id: trip._id },
      { $set: { updatedAt: new Date() } }
    );

    res.json({
      success: true,
      message: "Expense deleted.",
    });
  } catch (error) {
    console.error("Error deleting expense:", error);
    res.status(500).json({
      success: false,
      message: "Failed to delete expense.",
    });
  }
});

app.get("/api/settlement/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getAccessibleTripOr404(req, res, req.params.tripId);
    if (!trip) return;

    const requestedBaseCurrency = normalizeCurrency(req.query.baseCurrency || "USD");

    const expenses = await expensesCollection
      .find({ tripId: req.params.tripId })
      .toArray();

    const balances = {};
    const normalizedExpenses = [];

    for (const expense of expenses) {
      const originalAmount = Number(expense.amount) || 0;
      const originalCurrency = normalizeCurrency(expense.currency || requestedBaseCurrency);
      const savedBaseCurrency = normalizeCurrency(expense.baseCurrency || requestedBaseCurrency);

      let settlementAmount = 0;

      if (
        expense.convertedAmount !== undefined &&
        savedBaseCurrency === requestedBaseCurrency
      ) {
        settlementAmount = Number(expense.convertedAmount) || 0;
      } else if (originalCurrency === requestedBaseCurrency) {
        settlementAmount = originalAmount;
      } else {
        try {
          const conversion = await convertCurrency(
            originalAmount,
            originalCurrency,
            requestedBaseCurrency
          );
          settlementAmount = conversion.convertedAmount;
        } catch (conversionError) {
          console.error("Settlement conversion failed:", conversionError);
          settlementAmount = Number(expense.convertedAmount || originalAmount) || 0;
        }
      }

      settlementAmount = roundMoney(settlementAmount);

      normalizedExpenses.push({
        ...expense,
        settlementAmount,
        settlementCurrency: requestedBaseCurrency,
      });

      const paidBy = expense.paidBy || "Unknown";
      const sharedWith = Array.isArray(expense.sharedWith)
        ? expense.sharedWith
        : [];

      const participants = Array.from(new Set([paidBy, ...sharedWith])).filter(Boolean);

      if (participants.length === 0) continue;

      const share = settlementAmount / participants.length;

      if (!balances[paidBy]) balances[paidBy] = 0;
      balances[paidBy] += settlementAmount;

      participants.forEach((person) => {
        if (!balances[person]) balances[person] = 0;
        balances[person] -= share;
      });
    }

    const debtors = [];
    const creditors = [];

    Object.entries(balances).forEach(([person, balance]) => {
      const rounded = roundMoney(balance);

      if (rounded < -0.01) {
        debtors.push({
          person,
          amount: Math.abs(rounded),
        });
      } else if (rounded > 0.01) {
        creditors.push({
          person,
          amount: rounded,
        });
      }
    });

    const settlements = [];

    let i = 0;
    let j = 0;

    while (i < debtors.length && j < creditors.length) {
      const debtor = debtors[i];
      const creditor = creditors[j];
      const amount = Math.min(debtor.amount, creditor.amount);
      const roundedAmount = roundMoney(amount);

      if (roundedAmount > 0) {
        settlements.push({
          from: debtor.person,
          to: creditor.person,
          amount: roundedAmount,
          currency: requestedBaseCurrency,
        });
      }

      debtor.amount = roundMoney(debtor.amount - roundedAmount);
      creditor.amount = roundMoney(creditor.amount - roundedAmount);

      if (debtor.amount <= 0.01) i++;
      if (creditor.amount <= 0.01) j++;
    }

    const roundedBalances = {};

    Object.entries(balances).forEach(([person, balance]) => {
      roundedBalances[person] = roundMoney(balance);
    });

    res.json({
      success: true,
      baseCurrency: requestedBaseCurrency,
      balances: roundedBalances,
      settlements,
      normalizedExpenses,
      currentUserRole: getUserRoleForTrip(trip, req.user),
    });
  } catch (error) {
    console.error("Error calculating settlement:", error);
    res.status(500).json({
      success: false,
      message: "Failed to calculate settlement.",
      error: error.message,
    });
  }
});

/* =========================
   TEMPLATE ROUTES
========================= */

app.get("/api/templates", authRequired, async (req, res) => {
  try {
    const templates = await templatesCollection
      .find({ userId: req.userId })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      success: true,
      templates,
    });
  } catch (error) {
    console.error("Error fetching templates:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch templates.",
    });
  }
});

app.post("/api/templates/from-trip/:tripId", authRequired, async (req, res) => {
  try {
    const trip = await getAccessibleTripOr404(req, res, req.params.tripId);
    if (!trip) return;

    const template = {
      userId: req.userId,
      sourceTripId: req.params.tripId,
      title: req.body.title || trip.title || "Community Trip Template",
      destination: trip.destination || "",
      summary: trip.travelPlan?.summary || "",
      travelPlan: trip.travelPlan || {},
      createdAt: new Date(),
    };

    const result = await templatesCollection.insertOne(template);

    res.json({
      success: true,
      template: {
        ...template,
        _id: result.insertedId,
      },
    });
  } catch (error) {
    console.error("Error creating template:", error);
    res.status(500).json({
      success: false,
      message: "Failed to create template.",
    });
  }
});

app.post("/api/templates/:templateId/use", authRequired, async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.templateId);

    if (!objectId) {
      return res.status(400).json({
        success: false,
        message: "Invalid template ID.",
      });
    }

    const template = await templatesCollection.findOne({
      _id: objectId,
      userId: req.userId,
    });

    if (!template) {
      return res.status(404).json({
        success: false,
        message: "Template not found.",
      });
    }

    const tripDoc = {
      userId: req.userId,
      ownerUserId: req.userId,
      ownerEmail: req.userEmail,
      ownerName: req.user.name || "",
      title: `${template.title} Copy`,
      destination: template.destination || "",
      prompt: "Created from community template.",
      flightMode: "estimated",
      flightInfo: {},
      travelPlan: template.travelPlan || {},
      pinned: false,
      archived: false,
      projectId: "",
      projectName: "",
      collaborators: [],
      publicShareEnabled: false,
      shareToken: "",
      shareCreatedAt: null,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await tripsCollection.insertOne(tripDoc);

    await saveGeneratedItinerary(result.insertedId, template.travelPlan, req.userId, req.userId);

    res.json({
      success: true,
      tripId: result.insertedId.toString(),
      trip: {
        ...tripDoc,
        _id: result.insertedId,
        currentUserRole: "owner",
      },
    });
  } catch (error) {
    console.error("Error using template:", error);
    res.status(500).json({
      success: false,
      message: "Failed to use template.",
    });
  }
});

/* =========================
   PUBLIC SHARE API
========================= */

app.get("/api/public/share/:shareToken", async (req, res) => {
  try {
    const shareToken = String(req.params.shareToken || "").trim();

    const trip = await tripsCollection.findOne({
      shareToken,
      publicShareEnabled: true,
    });

    if (!trip) {
      return res.status(404).json({
        success: false,
        message: "Shared trip not found or link disabled.",
      });
    }

    const itinerary = await itineraryCollection
      .find({ tripId: trip._id.toString() })
      .sort({ day: 1, order: 1, startTime: 1 })
      .toArray();

    res.json({
      success: true,
      trip: {
        _id: trip._id,
        title: trip.title || "",
        destination: trip.destination || "",
        flightMode: trip.flightMode || "estimated",
        flightInfo: trip.flightInfo || {},
        travelPlan: trip.travelPlan || {},
        createdAt: trip.createdAt,
        updatedAt: trip.updatedAt,
      },
      itinerary,
    });
  } catch (error) {
    console.error("Error loading public share:", error);
    res.status(500).json({
      success: false,
      message: "Failed to load shared trip.",
    });
  }
});

/* =========================
   PRINT ROUTES
========================= */

app.get("/flight-print/:tripId", async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.tripId);

    if (!objectId) {
      return res.status(400).send("Invalid trip ID.");
    }

    const trip = await tripsCollection.findOne({ _id: objectId });

    if (!trip) {
      return res.status(404).send("Trip not found.");
    }

    const plan = trip.travelPlan || {};
    const flightInfo = trip.flightInfo || {};

    const flightModeText =
      trip.flightMode === "confirmed" ? "Confirmed Flight" : "Estimated Trip";

    const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>${escapeHtml(trip.title || "Flight Information")}</title>
  <style>
    body { font-family: Arial, sans-serif; color: #111827; margin: 40px; line-height: 1.6; background: #ffffff; }
    h1, h2, h3 { color: #111827; }
    .top { display: flex; justify-content: space-between; align-items: flex-start; gap: 20px; border-bottom: 2px solid #e5e7eb; padding-bottom: 20px; margin-bottom: 26px; }
    .badge { display: inline-block; background: #dbeafe; color: #1d4ed8; padding: 8px 14px; border-radius: 999px; font-size: 13px; font-weight: bold; }
    .section { margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid #e5e7eb; }
    .grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
    .card { border: 1px solid #e5e7eb; border-radius: 14px; padding: 14px; background: #f9fafb; }
    .label { color: #6b7280; font-size: 12px; font-weight: bold; margin-bottom: 6px; text-transform: uppercase; }
    .value { color: #111827; font-size: 16px; font-weight: bold; }
    .muted { color: #6b7280; }
    button { border: none; border-radius: 12px; background: #111827; color: white; padding: 11px 16px; font-weight: bold; cursor: pointer; margin-bottom: 20px; }
    @media print { button { display: none; } body { margin: 24px; } }
  </style>
</head>
<body>
  <button onclick="window.print()">Print / Save as PDF</button>

  <div class="top">
    <div>
      <h1>${escapeHtml(trip.title || "Travel Flight Information")}</h1>
      <p class="muted">${escapeHtml(trip.destination || "")}</p>
    </div>
    <span class="badge">${escapeHtml(flightModeText)}</span>
  </div>

  <div class="section">
    <h2>Flight / Trip Basics</h2>
    <div class="grid">
      <div class="card"><div class="label">Trip Mode</div><div class="value">${escapeHtml(flightModeText)}</div></div>
      <div class="card"><div class="label">Destination</div><div class="value">${escapeHtml(trip.destination || flightInfo.destination || "Not provided")}</div></div>
      <div class="card"><div class="label">Flight Number</div><div class="value">${escapeHtml(flightInfo.flightNumber || "Not provided")}</div></div>
      <div class="card"><div class="label">Flight Date</div><div class="value">${escapeHtml(flightInfo.flightDate || "Not provided")}</div></div>
      <div class="card"><div class="label">Origin</div><div class="value">${escapeHtml(flightInfo.origin || "Not provided")}</div></div>
      <div class="card"><div class="label">Hotel / Stay Area</div><div class="value">${escapeHtml(flightInfo.hotelArea || "Not decided yet")}</div></div>
      <div class="card"><div class="label">Estimated Start Date</div><div class="value">${escapeHtml(flightInfo.startDate || "Not provided")}</div></div>
      <div class="card"><div class="label">Trip Length</div><div class="value">${escapeHtml(flightInfo.tripDays || "Not provided")}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>AI Flight / Arrival Notes</h2>
    <p><strong>Status:</strong> ${escapeHtml(plan.flightPlan?.status || "")}</p>
    <p><strong>Explanation:</strong> ${escapeHtml(plan.flightPlan?.explanation || "")}</p>
    <p><strong>Arrival Strategy:</strong> ${escapeHtml(plan.flightPlan?.arrivalStrategy || "")}</p>
    <p><strong>Departure Strategy:</strong> ${escapeHtml(plan.flightPlan?.departureStrategy || "")}</p>
  </div>

  <div class="section">
    <h2>Trip Summary</h2>
    <p>${escapeHtml(plan.summary || "No summary available.")}</p>
  </div>
</body>
</html>
`;

    res.send(html);
  } catch (error) {
    console.error("Error rendering flight print page:", error);
    res.status(500).send("Failed to render flight print page.");
  }
});

function renderPrintableTripHtml(trip, itinerary, expenses, showButton, readOnlyText = "") {
  const plan = trip.travelPlan || {};
  const flightInfo = trip.flightInfo || {};

  const grouped = {};

  itinerary.forEach((item) => {
    if (!grouped[item.day]) grouped[item.day] = [];
    grouped[item.day].push(item);
  });

  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>${escapeHtml(trip.title || "Final Itinerary")}</title>
  <style>
    body { font-family: Arial, sans-serif; color: #111827; margin: 40px; line-height: 1.5; background: #ffffff; }
    h1, h2, h3 { color: #111827; }
    .top { border-bottom: 2px solid #e5e7eb; padding-bottom: 18px; margin-bottom: 26px; }
    .section { margin-bottom: 28px; padding-bottom: 18px; border-bottom: 1px solid #e5e7eb; }
    .muted { color: #6b7280; }
    .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 14px; }
    .info-card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 12px; background: #f9fafb; }
    .label { color: #6b7280; font-size: 12px; font-weight: bold; margin-bottom: 5px; }
    .value { font-weight: bold; }
    .activity-card { border: 1px solid #e5e7eb; border-radius: 12px; padding: 14px; margin: 10px 0; background: #f9fafb; page-break-inside: avoid; }
    .place-box { border: 1px solid #bfdbfe; border-radius: 12px; background: #eff6ff; padding: 10px; margin-top: 10px; }
    .time { font-weight: bold; color: #1d4ed8; }
    button { border: none; border-radius: 12px; background: #111827; color: white; padding: 11px 16px; font-weight: bold; cursor: pointer; margin-bottom: 20px; }
    a { color: #1d4ed8; }
    @media print { button { display: none; } body { margin: 24px; } .activity-card { page-break-inside: avoid; } }
  </style>
</head>
<body>
  ${showButton ? `<button onclick="window.print()">Print / Save as PDF</button>` : ""}

  <div class="top">
    <h1>${escapeHtml(trip.title || "Final Travel Itinerary")}</h1>
    <p class="muted">${escapeHtml(trip.destination || "")}</p>
    ${readOnlyText ? `<p class="muted">${escapeHtml(readOnlyText)}</p>` : ""}
    <div class="info-grid">
      <div class="info-card"><div class="label">Trip Mode</div><div class="value">${escapeHtml(trip.flightMode || "estimated")}</div></div>
      <div class="info-card"><div class="label">Flight / Start</div><div class="value">${escapeHtml(flightInfo.flightNumber || flightInfo.startDate || "Not provided")}</div></div>
      <div class="info-card"><div class="label">Hotel / Stay Area</div><div class="value">${escapeHtml(flightInfo.hotelArea || "Not decided yet")}</div></div>
    </div>
  </div>

  <div class="section">
    <h2>Trip Summary</h2>
    <p>${escapeHtml(plan.summary || "No summary available.")}</p>
  </div>

  <div class="section">
    <h2>Daily Itinerary</h2>
    ${
      Object.keys(grouped).length === 0
        ? "<p>No itinerary items found.</p>"
        : Object.keys(grouped)
            .sort((a, b) => Number(a) - Number(b))
            .map(
              (day) => `
        <h3>Day ${escapeHtml(day)}</h3>
        ${grouped[day]
          .map(
            (item) => `
          <div class="activity-card">
            <div class="time">${escapeHtml(item.startTime || "")} - ${escapeHtml(item.endTime || "")}</div>
            <div><strong>${escapeHtml(item.activity || "")}</strong></div>
            <div>${escapeHtml(item.location || "")}</div>
            <div class="muted">
              Transport: ${escapeHtml(item.transport || "")}
              ${item.estimatedTravelTime ? `(${escapeHtml(item.estimatedTravelTime)})` : ""}
            </div>
            <p>${escapeHtml(item.notes || "")}</p>

            ${
              item.placeName
                ? `
              <div class="place-box">
                <strong>${escapeHtml(item.placeName)}</strong><br />
                ${item.placeRating ? `Rating: ${escapeHtml(item.placeRating)} / 5` : ""}
                ${item.placeUserRatingCount ? ` · ${escapeHtml(item.placeUserRatingCount)} reviews` : ""}<br />
                ${item.placePriceLevel ? `Price: ${escapeHtml(item.placePriceLevel)}<br />` : ""}
                ${item.placeAddress ? `Address: ${escapeHtml(item.placeAddress)}<br />` : ""}
                ${item.whyRecommended ? `Why: ${escapeHtml(item.whyRecommended)}<br />` : ""}
                ${item.signatureItem ? `Highlight: ${escapeHtml(item.signatureItem)}<br />` : ""}
                ${
                  item.placeGoogleMapsUri
                    ? `<a href="${escapeHtml(item.placeGoogleMapsUri)}" target="_blank">Open in Google Maps</a>`
                    : ""
                }
              </div>
            `
                : ""
            }
          </div>
        `
          )
          .join("")}
      `
            )
            .join("")
    }
  </div>

  <div class="section">
    <h2>Budget Advice</h2>
    <p><strong>Estimated Total:</strong> ${escapeHtml(plan.budgetAdvice?.estimatedTotal || "")}</p>
    <p><strong>Daily Budget:</strong> ${escapeHtml(plan.budgetAdvice?.dailyBudget || "")}</p>
  </div>

  <div class="section">
    <h2>Recorded Expenses</h2>
    ${
      expenses.length === 0
        ? "<p>No expenses recorded.</p>"
        : expenses
            .map(
              (expense) => `
        <div class="activity-card">
          <strong>${escapeHtml(expense.description || "")}</strong><br />
          Original: ${escapeHtml(expense.amount || 0)} ${escapeHtml(expense.currency || "USD")}<br />
          Converted: ${escapeHtml(expense.convertedAmount || expense.amount || 0)} ${escapeHtml(expense.baseCurrency || expense.currency || "USD")}<br />
          Paid by ${escapeHtml(expense.paidBy || "")}
        </div>
      `
            )
            .join("")
    }
  </div>
</body>
</html>
`;
}

app.get("/trip-print/:tripId", async (req, res) => {
  try {
    const objectId = safeObjectId(req.params.tripId);

    if (!objectId) {
      return res.status(400).send("Invalid trip ID.");
    }

    const trip = await tripsCollection.findOne({ _id: objectId });

    if (!trip) {
      return res.status(404).send("Trip not found.");
    }

    const itinerary = await itineraryCollection
      .find({ tripId: req.params.tripId })
      .sort({ day: 1, order: 1, startTime: 1 })
      .toArray();

    const expenses = await expensesCollection
      .find({ tripId: req.params.tripId })
      .sort({ createdAt: -1 })
      .toArray();

    res.send(renderPrintableTripHtml(trip, itinerary, expenses, true));
  } catch (error) {
    console.error("Error rendering print page:", error);
    res.status(500).send("Failed to render print page.");
  }
});

app.get("/share-trip/:shareToken", async (req, res) => {
  try {
    const shareToken = String(req.params.shareToken || "").trim();

    const trip = await tripsCollection.findOne({
      shareToken,
      publicShareEnabled: true,
    });

    if (!trip) {
      return res.status(404).send("Shared trip not found or link disabled.");
    }

    const itinerary = await itineraryCollection
      .find({ tripId: trip._id.toString() })
      .sort({ day: 1, order: 1, startTime: 1 })
      .toArray();

    res.send(renderPrintableTripHtml(trip, itinerary, [], false, "Read-only shared trip"));
  } catch (error) {
    console.error("Error rendering shared trip:", error);
    res.status(500).send("Failed to render shared trip.");
  }
});

/* =========================
   START SERVER
========================= */

async function startServer() {
  try {
    await client.connect();

    db = client.db(process.env.DB_NAME || "travel_db");

    usersCollection = db.collection("users");
    tripsCollection = db.collection("trips");
    expensesCollection = db.collection("expenses");
    itineraryCollection = db.collection("itinerary_items");
    templatesCollection = db.collection("templates");
    projectsCollection = db.collection("projects");

    await usersCollection.createIndex({ email: 1 }, { unique: true });

    await tripsCollection.createIndex({ userId: 1, createdAt: -1 });
    await tripsCollection.createIndex({ ownerUserId: 1, createdAt: -1 });
    await tripsCollection.createIndex({ userId: 1, pinned: -1 });
    await tripsCollection.createIndex({ archived: 1 });
    await tripsCollection.createIndex({ shareToken: 1 });
    await tripsCollection.createIndex({ "collaborators.email": 1 });
    await tripsCollection.createIndex({ userId: 1, projectId: 1 });
    await tripsCollection.createIndex({ ownerUserId: 1, projectId: 1 });

    await expensesCollection.createIndex({ tripId: 1 });
    await expensesCollection.createIndex({ userId: 1, tripId: 1 });

    await itineraryCollection.createIndex({ tripId: 1, day: 1 });
    await itineraryCollection.createIndex({ userId: 1, tripId: 1, day: 1 });
    await itineraryCollection.createIndex({ userId: 1, tripId: 1, placeId: 1 });

    await templatesCollection.createIndex({ userId: 1, createdAt: -1 });

    await projectsCollection.createIndex({ userId: 1, createdAt: -1 });
    await projectsCollection.createIndex({ userId: 1, name: 1 });

    console.log("Connected to MongoDB!");
    console.log("Using database:", db.databaseName);
    console.log(
      GOOGLE_PLACES_API_KEY
        ? "Google Places API key loaded."
        : "Google Places API key missing. Real place data will be skipped."
    );

    app.listen(PORT, () => {
      console.log(`Server running at http://localhost:${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

startServer();