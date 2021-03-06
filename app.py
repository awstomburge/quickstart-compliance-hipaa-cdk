#!/usr/bin/env python3
# **********************************************************************************************************
# Imports
# **********************************************************************************************************
# ----------------------------------------------------------------------------------------------------------
import os
# ----------------------------------------------------------------------------------------------------------
from aws_cdk import core
# ----------------------------------------------------------------------------------------------------------
from quickstart_compliance_hipaa_cdk.main_stack import MainStack
from quickstart_compliance_hipaa_cdk.config_stack import ConfigStack
from quickstart_compliance_hipaa_cdk.log_stack import LogStack
from quickstart_compliance_hipaa_cdk.dev_stack import DevStack
from quickstart_compliance_hipaa_cdk.mgmt_stack import MgmtStack
from quickstart_compliance_hipaa_cdk.prod_stack import ProdStack
from quickstart_compliance_hipaa_cdk.tgw_stack import TgwStack
# ----------------------------------------------------------------------------------------------------------
# **********************************************************************************************************
# Initialize App
# **********************************************************************************************************
# ----------------------------------------------------------------------------------------------------------
app = core.App()
# **********************************************************************************************************
# Stacks
# **********************************************************************************************************
# Main Stack------------------------------------------------------------------------------------------------
main_stack = MainStack(app, 'main-stack')
# Config Stack----------------------------------------------------------------------------------------------
config_stack = ConfigStack(main_stack, 'config-stack', main_stack=main_stack)
# Log Stack-------------------------------------------------------------------------------------------------
log_stack = LogStack(main_stack, 'log-stack', main_stack=main_stack)
# Development Stack-----------------------------------------------------------------------------------------
dev_stack = DevStack(main_stack, 'dev-stack', main_stack=main_stack)
# # Production Stack------------------------------------------------------------------------------------------
prod_stack = ProdStack(main_stack, 'prod-stack', main_stack=main_stack)
# # Management Stack------------------------------------------------------------------------------------------
mgmt_stack = MgmtStack(main_stack, 'mgmt-stack', main_stack=main_stack)
# # Transit Gateway Stack-------------------------------------------------------------------------------------
tgw_stack = TgwStack(main_stack, 'tgw-stack',
    main_stack=main_stack,
    dev_stack=dev_stack,
    prod_stack=prod_stack,
    mgmt_stack=mgmt_stack
)
# **********************************************************************************************************
# Synthesize App
# **********************************************************************************************************
# ----------------------------------------------------------------------------------------------------------
app.synth()
