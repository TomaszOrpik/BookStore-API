using BookStore_API.Contracts;
using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BookStore_API.Services
{
    public class LoggerService : ILoggerService
    {
        private static ILogger logger = LogManager.GetCurrentClassLogger();

        public void LogDebug(string message)
        {
            logger.Debug("DEBUG " + message);
        }

        public void LogError(string message)
        {
            logger.Error("ERROR " + message);
        }

        public void LogInfo(string message)
        {
            logger.Info("INFO " + message);
        }

        public void LogWarn(string message)
        {
            logger.Warn("WARN " + message);
        }
    }
}
