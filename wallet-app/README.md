# Mirror Wallet - Production-Ready Ethereum Wallet Application

A secure, full-stack Ethereum wallet application with user authentication, encrypted keystore storage, and transaction capabilities.

## 🚀 Features

- **Secure Authentication**: Username/password with bcrypt hashing
- **Encrypted Wallet Storage**: Keystore encryption using ethers.js
- **Transaction Management**: Send ETH on Sepolia testnet
- **Balance Tracking**: Real-time balance updates
- **Transaction History**: Integration with Etherscan API
- **QR Code Generation**: Receive addresses via QR codes
- **Recovery Phrase Management**: Secure backup phrase handling
- **Production Ready**: Comprehensive error handling and security measures

## 🛠️ Tech Stack

### Backend
- **Node.js** with Express.js
- **PostgreSQL** database with Sequelize ORM
- **bcryptjs** for password hashing
- **CORS** for cross-origin requests
- **Rate limiting** and input validation

### Frontend
- **Vanilla JavaScript** with ethers.js
- **HTML5/CSS3** for responsive UI
- **QRCode.js** for address generation
- **Fetch API** for backend communication

### Deployment
- **Frontend**: Netlify (https://mrrorwallet.netlify.app/)
- **Backend**: Render (https://wallet-backend-jiph.onrender.com/)
- **Database**: PostgreSQL on Render

## 📋 Prerequisites

- Node.js 16+
- PostgreSQL database
- Render account for backend deployment
- Netlify account for frontend deployment

## 🚀 Deployment Instructions

### Backend Deployment (Render)

1. **Create a new Web Service** on Render
2. **Connect your repository** (GitHub/GitLab)
3. **Configure build settings**:
   - Build Command: `npm install`
   - Start Command: `npm start`
4. **Add environment variables** in Render dashboard:
   ```
   NODE_ENV=production
   DATABASE_URL=your_postgresql_connection_string
   ```
5. **Deploy** the service

### Frontend Deployment (Netlify)

1. **Connect your repository** to Netlify
2. **Configure build settings**:
   - Build Command: `echo "Frontend is static HTML/CSS/JS - no build required"`
   - Publish Directory: `frontend/`
3. **Add environment variables** (if needed):
   ```
   API_BASE_URL=https://wallet-backend-jiph.onrender.com
   ```
4. **Deploy** the site

### Database Setup

1. **Create PostgreSQL database** on Render or your preferred provider
2. **Get connection string** and add to Render environment variables
3. **Database schema** will be automatically created by Sequelize

## 🔧 Environment Variables

### Required
- `DATABASE_URL`: PostgreSQL connection string
- `NODE_ENV`: Environment (development/production)

### Optional
- `PORT`: Server port (default: 3000)

## 🔒 Security Features

- **Input Validation**: Comprehensive client and server-side validation
- **Rate Limiting**: 5 requests per 15-minute window per IP
- **Password Requirements**: Minimum 8 characters, weak password detection
- **HTTPS Enforcement**: Automatic redirect to HTTPS in production
- **Security Headers**: XSS protection, content sniffing prevention
- **CORS Configuration**: Restricted to allowed origins only
- **SQL Injection Prevention**: Parameterized queries via Sequelize

## 📊 API Endpoints

### Authentication
- `POST /signup` - User registration
- `POST /login` - User login
- `POST /import` - Import existing wallet
- `POST /get-keystore` - Retrieve encrypted keystore

### Monitoring
- `GET /health` - Health check endpoint
- `GET /api/status` - API status and information

## 🧪 Testing

### Manual Testing
1. **Create Account**: Register with username/password
2. **Login**: Use credentials to access wallet
3. **Check Balance**: View ETH balance on dashboard
4. **Send Transaction**: Send test ETH to another address
5. **View History**: Check transaction history

### Health Checks
- Backend: https://wallet-backend-jiph.onrender.com/health
- Frontend: https://mrrorwallet.netlify.app/

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check DATABASE_URL environment variable
   - Verify PostgreSQL service is running
   - Check database credentials

2. **CORS Errors**
   - Ensure frontend URL is in allowed origins
   - Check if request includes credentials

3. **Transaction Failures**
   - Verify sufficient test ETH balance
   - Check gas price and limits
   - Ensure recipient address is valid

4. **Login Issues**
   - Verify username/password combination
   - Check database connectivity
   - Review server logs for errors

### Debug Mode
Set `NODE_ENV=development` for detailed error messages and logging.

## 📝 Development Notes

- All sensitive data is encrypted before storage
- Recovery phrases are never stored in plain text
- Database uses SSL in production
- Rate limiting prevents abuse
- Input validation prevents injection attacks

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## 📄 License

This project is licensed under the ISC License.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review server logs on Render
3. Test API endpoints directly
4. Verify environment variables

---

**Production Status**: ✅ Ready for production use
**Last Updated**: 2024
**Version**: 1.0.0