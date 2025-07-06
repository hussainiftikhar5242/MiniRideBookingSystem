const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const auth = require('basic-auth');
const cors = require('cors');
const bcrypt = require('bcrypt'); 

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database(':memory:');

const SALT_ROUNDS = 10;

db.serialize(() => {
  db.run(`
    CREATE TABLE User (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('passenger', 'driver')),
      is_available BOOLEAN,
      balance REAL NOT NULL DEFAULT 0.0
    )
  `);
  db.run(`
    CREATE TABLE RideRequest (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      passenger_id INTEGER NOT NULL,
      pickup_location TEXT NOT NULL,
      drop_location TEXT NOT NULL,
      ride_type TEXT NOT NULL CHECK(ride_type IN ('bike', 'car', 'rickshaw')),
      payment REAL NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('requested', 'cancelled')),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (passenger_id) REFERENCES User(id)
    )
  `);
  db.run(`
    CREATE TABLE Ride (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      passenger_id INTEGER NOT NULL,
      driver_id INTEGER NOT NULL,
      pickup_location TEXT NOT NULL,
      drop_location TEXT NOT NULL,
      ride_type TEXT NOT NULL CHECK(ride_type IN ('bike', 'car', 'rickshaw')),
      payment REAL NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('accepted', 'in_progress', 'completed', 'cancelled')),
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (passenger_id) REFERENCES User(id),
      FOREIGN KEY (driver_id) REFERENCES User(id)
    )
  `);
  db.run(`
    CREATE TABLE RideRejection (
      ride_request_id INTEGER NOT NULL,
      driver_id INTEGER NOT NULL,
      PRIMARY KEY (ride_request_id, driver_id),
      FOREIGN KEY (ride_request_id) REFERENCES RideRequest(id),
      FOREIGN KEY (driver_id) REFERENCES User(id)
    )
  `);
  db.run(`
    CREATE TABLE Payment (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ride_id INTEGER NOT NULL,
      driver_id INTEGER NOT NULL,
      amount REAL NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (ride_id) REFERENCES Ride(id),
      FOREIGN KEY (driver_id) REFERENCES User(id)
    )
  `);
});

// Middleware for Basic Authentication
const authenticateBasic = (req, res, next) => {
  const credentials = auth(req);
  if (!credentials || !credentials.name || !credentials.pass) {
    res.set('WWW-Authenticate', 'Basic realm="Ride Booking System"');
    return res.status(401).json({ error: 'Access denied' });
  }
  db.get('SELECT * FROM User WHERE email = ?', [credentials.name], (err, user) => {
    if (err) {
      console.error('Error in authenticateBasic:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      res.set('WWW-Authenticate', 'Basic realm="Ride Booking System"');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    bcrypt.compare(credentials.pass, user.password, (err, result) => {
      if (err || !result) {
        res.set('WWW-Authenticate', 'Basic realm="Ride Booking System"');
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      req.user = { id: user.id, type: user.type, is_available: user.is_available, balance: user.balance };
      next();
    });
  });
};

// =========================== Request to Register =========================================

app.post('/register', (req, res) => {
  const { name, email, password, type } = req.body;
  if (!name || !email || !password || !type || !['passenger', 'driver'].includes(type)) {
    return res.status(400).json({ error: 'Invalid input' });
  }
  bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err.message);
      return res.status(500).json({ error: 'Failed to register user' });
    }
    db.run(
      'INSERT INTO User (name, email, password, type, is_available, balance) VALUES (?, ?, ?, ?, ?, ?)',
      [name, email, hash, type, type === 'driver' ? true : null, 0.0],
      (err) => {
        if (err) {
          console.error('Error registering user:', err.message);
          return res.status(400).json({ error: 'Email already exists' });
        }
        res.status(201).json({ message: 'User registered' });
      }
    );
  });
});

// =========================== Request to Login (for testing Basic Auth credentials) ===========================================  
app.post('/login', authenticateBasic, (req, res) => {
  res.json({ message: 'Login successful', user: { id: req.user.id, type: req.user.type, is_available: req.user.is_available, balance: req.user.balance } });
});

//=========================== Request to Request a Ride ========================================
app.post('/rides', authenticateBasic, (req, res) => {
  if (req.user.type !== 'passenger') return res.status(403).json({ error: 'Only passengers can request rides' });
  const { pickup_location, drop_location, ride_type, payment } = req.body;
  if (!pickup_location || !drop_location || !['bike', 'car', 'rickshaw'].includes(ride_type) || typeof payment !== 'number' || payment <= 0) {
    return res.status(400).json({ error: 'Invalid ride details or payment must be a positive number' });
  }
  db.get(
    'SELECT * FROM RideRequest WHERE passenger_id = ? AND is_active = TRUE',
    [req.user.id],
    (err, existingRequest) => {
      if (err) {
        console.error('Error checking existing ride request:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      if (existingRequest) {
        const errorMessage = 'Only one active ride request allowed at a time';
        console.error(errorMessage, { passenger_id: req.user.id, existing_request_id: existingRequest.id });
        return res.status(400).json({ error: errorMessage });
      }
      db.get(
        'SELECT * FROM Ride WHERE passenger_id = ? AND is_active = TRUE',
        [req.user.id],
        (err, existingRide) => {
          if (err) {
            console.error('Error checking existing ride:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }
          if (existingRide) {
            const errorMessage = 'Only one active ride allowed at a time';
            console.error(errorMessage, { passenger_id: req.user.id, existing_ride_id: existingRide.id });
            return res.status(400).json({ error: errorMessage });
          }
          createNewRideRequest(req, res, pickup_location, drop_location, ride_type, payment);
        }
      );
    }
  );
});

//=========================== Helper function to create a new ride request ===========================

function createNewRideRequest(req, res, pickup_location, drop_location, ride_type, payment) {
  db.run(
    'INSERT INTO RideRequest (passenger_id, pickup_location, drop_location, ride_type, payment, status, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [req.user.id, pickup_location, drop_location, ride_type, payment, 'requested', true],
    function (err) {
      if (err) {
        console.error('Error creating ride request:', err.message);
        return res.status(500).json({ error: 'Failed to request ride' });
      }
      res.status(201).json({ ride_request_id: this.lastID });
    }
  );
}

// =========================== Request to Get Current Ride or Request ===========================

app.get('/rides/current', authenticateBasic, (req, res) => {
  if (req.user.type !== 'passenger') return res.status(403).json({ error: 'Only passengers can view current ride' });
  db.get(
    'SELECT * FROM RideRequest WHERE passenger_id = ? AND is_active = TRUE ORDER BY created_at DESC LIMIT 1',
    [req.user.id],
    (err, rideRequest) => {
      if (err) {
        console.error('Error fetching current ride request:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      if (rideRequest) {
        return res.json({ ...rideRequest, source: 'RideRequest' });
      }
      db.get(
        'SELECT * FROM Ride WHERE passenger_id = ? AND is_active = TRUE ORDER BY created_at DESC LIMIT 1',
        [req.user.id],
        (err, ride) => {
          if (err) {
            console.error('Error fetching current ride:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }
          res.json(ride ? { ...ride, source: 'Ride' } : null);
        }
      );
    }
  );
});

// =========================== Request to Get Ride History ===========================

app.get('/rides/history', authenticateBasic, (req, res) => {
  if (req.user.type !== 'passenger') return res.status(403).json({ error: 'Only passengers can view history' });
  db.all(
`SELECT id, passenger_id, NULL AS driver_id, pickup_location, drop_location, ride_type, payment, status, is_active, created_at, 
       'RideRequest' AS source
FROM RideRequest 
WHERE passenger_id = ? AND status = 'cancelled'
UNION ALL
SELECT id, passenger_id, driver_id, pickup_location, drop_location, ride_type, payment, status, is_active, created_at, 
       'Ride' AS source 
FROM Ride 
WHERE passenger_id = ? AND status IN ('completed', 'cancelled') 
ORDER BY created_at DESC`,

    [req.user.id, req.user.id],
    (err, history) => {
      if (err) {
        console.error('Error fetching ride history:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(history);
    }
  );
});

//=========================== Request to Get Driver Balance ===========================

app.get('/users/balance', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') return res.status(403).json({ error: 'Only drivers can view balance' });
  res.json({ balance: req.user.balance });
});

//=========================== Request to Get Available Ride Requests ===========================

app.get('/rides/available', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') return res.status(403).json({ error: 'Only drivers can view available rides' });
  if (!req.user.is_available) return res.status(403).json({ error: 'Driver is not available' });
  db.all(
    'SELECT * FROM RideRequest WHERE status = "requested" AND is_active = TRUE AND id NOT IN (SELECT ride_request_id FROM RideRejection WHERE driver_id = ?)',
    [req.user.id],
    (err, rideRequests) => {
      if (err) {
        console.error('Error fetching available ride requests:', err.message);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      res.json(rideRequests);
    }
  );
});

//=========================== Request to Accept a Ride Request ===========================

app.post('/rides/:id/accept', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') return res.status(403).json({ error: 'Only drivers can accept rides' });
  if (!req.user.is_available) return res.status(403).json({ error: 'Driver is not available to accept rides' });
  db.get(
    'SELECT * FROM Ride WHERE driver_id = ? AND is_active = TRUE',
    [req.user.id],
    (err, existingRide) => {
      if (err) {
        console.error('Error checking existing ride for driver:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      if (existingRide) {
        const errorMessage = 'Only one active ride allowed at a time for a driver';
        console.error(errorMessage, { driver_id: req.user.id, existing_ride_id: existingRide.id });
        return res.status(400).json({ error: errorMessage });
      }
      db.get(
        'SELECT * FROM RideRequest WHERE id = ? AND status = "requested" AND is_active = TRUE',
        [req.params.id],
        (err, rideRequest) => {
          if (err) {
            console.error('Error checking ride request:', err.message);
            return res.status(500).json({ error: 'Database error' });
          }
          if (!rideRequest) return res.status(400).json({ error: 'Ride request not available' });
          db.run(
            'INSERT INTO Ride (passenger_id, driver_id, pickup_location, drop_location, ride_type, payment, status, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [rideRequest.passenger_id, req.user.id, rideRequest.pickup_location, rideRequest.drop_location, rideRequest.ride_type, rideRequest.payment, 'accepted', true, rideRequest.created_at],
            function (err) {
              if (err) {
                console.error('Error creating ride:', err.message);
                return res.status(500).json({ error: 'Failed to accept ride' });
              }
              const rideId = this.lastID;
              db.run(
                'DELETE FROM RideRequest WHERE id = ?',
                [req.params.id],
                (err) => {
                  if (err) {
                    console.error('Error deleting ride request:', err.message);
                    return res.status(500).json({ error: 'Failed to delete ride request' });
                  }
                  res.json({ message: 'Ride accepted', ride_id: rideId });
                }
              );
            }
          );
        }
      );
    }
  );
});

//=========================== Request to Reject a Ride Request ============================

app.post('/rides/:id/reject', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') return res.status(403).json({ error: 'Only drivers can reject rides' });
  if (!req.user.is_available) return res.status(403).json({ error: 'Driver is not available to reject rides' });
  db.get(
    'SELECT * FROM RideRequest WHERE id = ? AND status = "requested" AND is_active = TRUE',
    [req.params.id],
    (err, rideRequest) => {
      if (err) {
        console.error('Error checking ride request for rejection:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!rideRequest) return res.status(400).json({ error: 'Ride request not available' });
      db.run(
        'INSERT INTO RideRejection (ride_request_id, driver_id) VALUES (?, ?)',
        [req.params.id, req.user.id],
        (err) => {
          if (err) {
            console.error('Error recording rejection:', err.message);
            return res.status(500).json({ error: 'Failed to record rejection' });
          }
          res.json({ message: 'Ride request rejected' });
        }
      );
    }
  );
});

// =========================== Request to Update Ride Status ===========================

app.post('/rides/:id/update_status', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') return res.status(403).json({ error: 'Only drivers can update status' });
  const { status } = req.body;
  if (!['in_progress', 'completed', 'cancelled'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  const isActive = ['accepted', 'in_progress'].includes(status) ? true : false;
  db.get(
    'SELECT * FROM Ride WHERE id = ? AND driver_id = ?',
    [req.params.id, req.user.id],
    (err, ride) => {
      if (err) {
        console.error('Error fetching ride for status update:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!ride) return res.status(400).json({ error: 'Ride not found or not assigned to driver' });
      if (ride.status === 'completed') {
        return res.status(400).json({ error: 'Cannot update status of a completed ride' });
      }
      db.run(
        'UPDATE Ride SET status = ?, is_active = ? WHERE id = ?',
        [status, isActive, req.params.id],
        function (err) {
          if (err) {
            console.error('Error updating ride status:', err.message);
            return res.status(500).json({ error: 'Status update failed' });
          }
          if (this.changes === 0) return res.status(400).json({ error: 'Failed to update status' });
          if (status === 'completed') {
            db.run(
              'INSERT INTO Payment (ride_id, driver_id, amount) VALUES (?, ?, ?)',
              [req.params.id, req.user.id, ride.payment],
              (err) => {
                if (err) {
                  console.error('Error recording payment:', err.message);
                  return res.status(500).json({ error: 'Failed to record payment' });
                }
                db.run(
                  'UPDATE User SET balance = balance + ? WHERE id = ?',
                  [ride.payment, req.user.id],
                  (err) => {
                    if (err) {
                      console.error('Error updating driver balance:', err.message);
                      return res.status(500).json({ error: 'Failed to update driver balance' });
                    }
                    res.json({ message: 'Status updated and payment processed', amount: ride.payment });
                  }
                );
              }
            );
          } else {
            res.json({ message: 'Status updated' });
          }
        }
      );
    }
  );
});

//=========================== Request to Cancel a Ride or Request ===========================

app.post('/rides/:id/cancel', authenticateBasic, (req, res) => {
  if (req.user.type !== 'passenger') return res.status(403).json({ error: 'Only passengers can cancel rides' });
  db.get(
    'SELECT * FROM RideRequest WHERE id = ? AND passenger_id = ? AND status = "requested" AND is_active = TRUE',
    [req.params.id, req.user.id],
    (err, rideRequest) => {
      if (err) {
        console.error('Error checking ride request for cancellation:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      if (rideRequest) {
        db.run(
          'UPDATE RideRequest SET status = "cancelled", is_active = FALSE WHERE id = ?',
          [req.params.id],
          function (err) {
            if (err) {
              console.error('Error cancelling ride request:', err.message);
              return res.status(500).json({ error: 'Database error' });
            }
            if (this.changes === 0) return res.status(400).json({ error: 'Cannot cancel ride request' });
            res.json({ message: 'Ride request cancelled' });
          }
        );
      } else {
        db.run(
          'UPDATE Ride SET status = "cancelled", is_active = FALSE WHERE id = ? AND passenger_id = ? AND status = "accepted"',
          [req.params.id, req.user.id],
          function (err) {
            if (err) {
              console.error('Error cancelling ride:', err.message);
              return res.status(500).json({ error: 'Database error' });
            }
            if (this.changes === 0) return res.status(400).json({ error: 'Cannot cancel ride' });
            res.json({ message: 'Ride cancelled' });
          }
        );
      }
    }
  );
});

//=========================== Request to Get All Payment Records for Driver ===========================

app.get('/users/payments', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') 
    return res.status(403).json({ error: 'Only drivers can view payment records' });
  db.all(
    'SELECT id, ride_id, amount, created_at FROM Payment WHERE driver_id = ? ORDER BY created_at DESC',
    [req.user.id],
    (err, payments) => {
      if (err) {
        console.error('Error fetching payment records:', err.message);
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(payments);
    }
  );
});

//=========================== Request to Update Driver Availability ===========================

app.put('/users/availability', authenticateBasic, (req, res) => {
  if (req.user.type !== 'driver') 
    return res.status(403).json({ error: 'Only drivers can update availability' });
  const { is_available } = req.body;
  db.run(
    'UPDATE User SET is_available = ? WHERE id = ?',
    [is_available, req.user.id],
    (err) => {
      if (err) {
        console.error('Error updating availability:', err.message);
        return res.status(500).json({ error: 'Failed to update availability' });
      }
      res.json({ message: 'Availability updated' });
    }
  );
});

app.listen(3000, () => console.log('Server running on port 3000'));