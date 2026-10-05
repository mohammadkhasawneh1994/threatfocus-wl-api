import logging
import sys
from layers.aws.python.aws_lambda_powertools import Logger, Tracer

logger = Logger(service="watchlist-service")
tracer = Tracer(service="watchlist-service")


def setup_logging() -> None:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )