import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine, or_
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    target_value = Column(String(255), index=True, nullable=False)
    target_type = Column(String(64), nullable=False, default="generic")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_results = relationship("ScanResult", back_populates="target")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False, index=True)
    module_name = Column(String(128), nullable=False, index=True)
    status = Column(String(32), default="success")
    raw_result = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    target = relationship("Target", back_populates="scan_results")
    entities = relationship("EntityProfile", back_populates="scan_result", cascade="all, delete-orphan")


class EntityProfile(Base):
    __tablename__ = "entity_profiles"

    id = Column(Integer, primary_key=True)
    scan_result_id = Column(Integer, ForeignKey("scan_results.id"), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False, index=True)
    entity_value = Column(String(512), nullable=False, index=True)
    metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_result = relationship("ScanResult", back_populates="entities")


class Relationship(Base):
    __tablename__ = "relationships"

    id = Column(Integer, primary_key=True)
    source_entity_id = Column(Integer, ForeignKey("entity_profiles.id"), nullable=False, index=True)
    target_entity_id = Column(Integer, ForeignKey("entity_profiles.id"), nullable=False, index=True)
    relation_type = Column(String(64), nullable=False, default="related_to")
    created_at = Column(DateTime, default=datetime.utcnow)


class ReportSnapshot(Base):
    __tablename__ = "report_snapshots"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    content_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class DatabaseManager:
    def __init__(self, db_url: str = "sqlite:///amateur_osint.db"):
        self.engine = create_engine(db_url, future=True)
        self.SessionLocal = sessionmaker(bind=self.engine, autoflush=False, autocommit=False)

    def init_db(self) -> None:
        Base.metadata.create_all(bind=self.engine)

    def _to_json(self, payload: Any) -> str:
        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except Exception:
            return json.dumps({"raw": str(payload)}, ensure_ascii=False)

    def get_or_create_target(self, session, target_value: str, target_type: str) -> Target:
        target = (
            session.query(Target)
            .filter(Target.target_value == target_value, Target.target_type == target_type)
            .order_by(Target.id.desc())
            .first()
        )
        if target:
            return target

        target = Target(target_value=target_value, target_type=target_type)
        session.add(target)
        session.flush()
        return target

    def save_scan_result(
        self,
        module_name: str,
        target_value: str,
        target_type: str,
        raw_result: Any,
        status: str = "success",
    ) -> Optional[int]:
        session = self.SessionLocal()
        try:
            target = self.get_or_create_target(session, target_value=target_value, target_type=target_type)
            scan = ScanResult(
                target_id=target.id,
                module_name=module_name,
                status=status,
                raw_result=self._to_json(raw_result),
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan.id
        except Exception:
            session.rollback()
            return None
        finally:
            session.close()

    def save_entities(self, scan_result_id: int, entities: List[Dict[str, Any]]) -> Dict[str, int]:
        session = self.SessionLocal()
        ref_to_id: Dict[str, int] = {}
        try:
            for idx, item in enumerate(entities, start=1):
                ref = item.get("ref") or f"entity_{idx}"
                entity = EntityProfile(
                    scan_result_id=scan_result_id,
                    entity_type=item.get("entity_type", "Unknown"),
                    entity_value=str(item.get("entity_value", "N/A")),
                    metadata_json=self._to_json(item.get("metadata", {})),
                )
                session.add(entity)
                session.flush()
                ref_to_id[ref] = entity.id
            session.commit()
            return ref_to_id
        except Exception:
            session.rollback()
            return {}
        finally:
            session.close()

    def save_relationships(self, relationships: List[Dict[str, Any]], ref_to_id: Dict[str, int]) -> None:
        if not relationships or not ref_to_id:
            return

        session = self.SessionLocal()
        try:
            for rel in relationships:
                source_id = ref_to_id.get(rel.get("source_ref"))
                target_id = ref_to_id.get(rel.get("target_ref"))
                if not source_id or not target_id:
                    continue

                session.add(
                    Relationship(
                        source_entity_id=source_id,
                        target_entity_id=target_id,
                        relation_type=rel.get("relation_type", "related_to"),
                    )
                )
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def save_report_snapshot(self, title: str, content: Dict[str, Any]) -> None:
        session = self.SessionLocal()
        try:
            session.add(ReportSnapshot(title=title, content_json=self._to_json(content)))
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        session = self.SessionLocal()
        try:
            rows = (
                session.query(ScanResult, Target)
                .join(Target, Target.id == ScanResult.target_id)
                .order_by(ScanResult.created_at.desc())
                .limit(limit)
                .all()
            )
            history = []
            for scan, target in rows:
                history.append(
                    {
                        "scan_id": scan.id,
                        "module": scan.module_name,
                        "status": scan.status,
                        "target": target.target_value,
                        "target_type": target.target_type,
                        "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    }
                )
            return history
        except Exception:
            return []
        finally:
            session.close()

    def get_scan_payload(self, scan_id: int) -> Dict[str, Any]:
        session = self.SessionLocal()
        try:
            scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
            if not scan:
                return {}
            return json.loads(scan.raw_result)
        except Exception:
            return {}
        finally:
            session.close()

    def get_graph_data(self, scan_id: Optional[int] = None) -> Dict[str, List[Dict[str, Any]]]:
        session = self.SessionLocal()
        try:
            entity_query = session.query(EntityProfile)
            if scan_id is not None:
                entity_query = entity_query.filter(EntityProfile.scan_result_id == scan_id)

            entities = entity_query.all()
            entity_ids = {e.id for e in entities}
            if not entity_ids:
                return {"nodes": [], "edges": []}

            relationships = (
                session.query(Relationship)
                .filter(
                    Relationship.source_entity_id.in_(entity_ids),
                    Relationship.target_entity_id.in_(entity_ids),
                )
                .all()
            )

            nodes = [
                {
                    "id": e.id,
                    "label": e.entity_value,
                    "group": e.entity_type,
                    "title": f"{e.entity_type}: {e.entity_value}",
                }
                for e in entities
            ]
            edges = [
                {
                    "from": rel.source_entity_id,
                    "to": rel.target_entity_id,
                    "label": rel.relation_type,
                }
                for rel in relationships
            ]
            return {"nodes": nodes, "edges": edges}
        except Exception:
            return {"nodes": [], "edges": []}
        finally:
            session.close()

    def cleanup_old_scans(self, retention_days: int) -> Dict[str, int]:
        session = self.SessionLocal()
        try:
            safe_days = max(1, int(retention_days))
            threshold = datetime.utcnow() - timedelta(days=safe_days)

            old_scan_ids = [
                row[0]
                for row in session.query(ScanResult.id)
                .filter(ScanResult.created_at < threshold)
                .all()
            ]

            if not old_scan_ids:
                return {
                    "scans_deleted": 0,
                    "entities_deleted": 0,
                    "relationships_deleted": 0,
                    "reports_deleted": 0,
                    "targets_deleted": 0,
                }

            old_entity_ids = [
                row[0]
                for row in session.query(EntityProfile.id)
                .filter(EntityProfile.scan_result_id.in_(old_scan_ids))
                .all()
            ]

            rel_deleted = 0
            if old_entity_ids:
                rel_deleted = (
                    session.query(Relationship)
                    .filter(
                        or_(
                            Relationship.source_entity_id.in_(old_entity_ids),
                            Relationship.target_entity_id.in_(old_entity_ids),
                        )
                    )
                    .delete(synchronize_session=False)
                )

            ent_deleted = (
                session.query(EntityProfile)
                .filter(EntityProfile.scan_result_id.in_(old_scan_ids))
                .delete(synchronize_session=False)
            )

            scan_deleted = (
                session.query(ScanResult)
                .filter(ScanResult.id.in_(old_scan_ids))
                .delete(synchronize_session=False)
            )

            report_deleted = (
                session.query(ReportSnapshot)
                .filter(ReportSnapshot.created_at < threshold)
                .delete(synchronize_session=False)
            )

            orphan_targets = (
                session.query(Target)
                .outerjoin(ScanResult, ScanResult.target_id == Target.id)
                .filter(ScanResult.id.is_(None))
            )
            target_deleted = orphan_targets.delete(synchronize_session=False)

            session.commit()
            return {
                "scans_deleted": int(scan_deleted or 0),
                "entities_deleted": int(ent_deleted or 0),
                "relationships_deleted": int(rel_deleted or 0),
                "reports_deleted": int(report_deleted or 0),
                "targets_deleted": int(target_deleted or 0),
            }
        except Exception:
            session.rollback()
            return {
                "scans_deleted": 0,
                "entities_deleted": 0,
                "relationships_deleted": 0,
                "reports_deleted": 0,
                "targets_deleted": 0,
            }
        finally:
            session.close()
