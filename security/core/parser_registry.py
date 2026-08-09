"""
parser_registry.py

Enterprise Parser Registry

Responsible for registering and executing
all available parser modules.

Every new parser should register itself here.

Example
-------
registry.register("hadolint", HadolintParser)
registry.register("trivy", TrivyParser)
"""

from security.common.logger import logger

from security.core.exceptions import (
    ParserRegistrationError,
    ParserError
)


class ParserRegistry:

    ###########################################################
    # Constructor
    ###########################################################

    def __init__(self):

        self.parsers = {}

    ###########################################################
    # Register Parser
    ###########################################################

    def register(self, name, parser_class):

        name = name.lower()

        if name in self.parsers:

            raise ParserRegistrationError(

                f"Parser '{name}' already registered."

            )

        self.parsers[name] = parser_class

        logger.info(

            f"Registered parser: {name}"

        )

    ###########################################################
    # Get Parser
    ###########################################################

    def get(self, name):

        return self.parsers.get(

            name.lower()

        )

    ###########################################################
    # List Parsers
    ###########################################################

    def list_parsers(self):

        return sorted(

            self.parsers.keys()

        )

    ###########################################################
    # Execute One Parser
    ###########################################################

    def run(self, name):

        parser_class = self.get(name)

        if parser_class is None:

            raise ParserError(

                f"Unknown parser: {name}"

            )

        logger.info(

            f"Running parser: {name}"

        )

        parser = parser_class()

        parser.run()

    ###########################################################
    # Execute All Parsers
    ###########################################################

    def run_all(self):

        logger.info(

            "=" * 70

        )

        logger.info(

            "Running all registered parsers..."

        )

        logger.info(

            "=" * 70

        )

        for name in self.list_parsers():

            try:

                logger.info(

                    f"Starting {name}"

                )

                parser = self.parsers[name]()

                parser.run()

                logger.info(

                    f"{name} completed successfully."

                )

            except Exception as ex:

                logger.exception(

                    f"{name} failed."

                )

                raise ParserError(

                    f"{name} parser failed."

                ) from ex

        logger.info(

            "=" * 70

        )

        logger.info(

            "All parsers completed successfully."

        )

        logger.info(

            "=" * 70
        )


###########################################################
# Global Registry
###########################################################

registry = ParserRegistry()
