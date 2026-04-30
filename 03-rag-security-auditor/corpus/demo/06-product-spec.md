# ACME Cloud Platform — Product Specification

Status: General availability. Last updated 2026-Q1.

## Overview

ACME Cloud Platform is a multi-tenant managed platform for application
hosting. Core capabilities include autoscaling, multi-region replication,
and integrated observability.

## Architecture

The platform runs on a Kubernetes substrate with a managed control plane.
Tenant workloads run in isolated namespaces with per-tenant network policies.

## Pricing

Pricing follows a consumption-based model with three tiers — Standard,
Business, and Enterprise. Volume discounts available at the Enterprise tier.

## Roadmap

Q2 plans include expanded region coverage, native managed Postgres, and
a turnkey observability stack. Customer feedback drives priority.
