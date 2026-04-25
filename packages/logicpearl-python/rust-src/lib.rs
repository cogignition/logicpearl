use logicpearl_core::LogicPearlError;
use logicpearl_engine::{
    EngineBatchExecution, EngineExecutionEnvelope, EngineSingleExecution, LogicPearlEngine,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{
    PyAny, PyBool, PyDict, PyFloat, PyInt, PyList, PyModule, PyString, PyTuple, PyType,
};
use serde::Serialize;
use serde_json::{Map, Number, Value};

#[pyclass(name = "LogicPearlEngine")]
struct PyLogicPearlEngine {
    inner: LogicPearlEngine,
}

#[pymethods]
impl PyLogicPearlEngine {
    #[classmethod]
    fn from_path(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: LogicPearlEngine::from_path(path).map_err(to_py_runtime_error)?,
        })
    }

    #[classmethod]
    fn from_artifact_path(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: LogicPearlEngine::from_artifact_path(path).map_err(to_py_runtime_error)?,
        })
    }

    #[classmethod]
    fn from_pipeline_path(_cls: &Bound<'_, PyType>, path: &str) -> PyResult<Self> {
        Ok(Self {
            inner: LogicPearlEngine::from_pipeline_path(path).map_err(to_py_runtime_error)?,
        })
    }

    #[getter]
    fn kind(&self) -> String {
        serde_json::to_string(&self.inner.kind())
            .ok()
            .and_then(|text| serde_json::from_str::<String>(&text).ok())
            .unwrap_or_else(|| "unknown".to_string())
    }

    #[getter]
    fn source_path(&self) -> String {
        self.inner.source_path().display().to_string()
    }

    /// Run an artifact or pipeline and return the full engine envelope.
    fn run(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let input = py_any_to_json(input)?;
        let result = py
            .allow_threads(|| self.inner.run_json_value(&input))
            .map_err(to_py_runtime_error)?;
        serialize_to_python(py, &result)
    }

    /// Run one input and return the full engine envelope.
    fn run_single(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let input = py_any_to_json(input)?;
        let result = py
            .allow_threads(|| self.inner.run_single_json(&input))
            .map_err(to_py_runtime_error)?;
        serialize_to_python(py, &result)
    }

    /// Run a list of inputs and return the full engine envelope.
    fn run_batch(&self, py: Python<'_>, inputs: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let value = py_any_to_json(inputs)?;
        let items = value.as_array().ok_or_else(|| {
            PyValueError::new_err("run_batch expects a JSON-compatible Python list")
        })?;
        let result = py
            .allow_threads(|| self.inner.run_batch_json(items))
            .map_err(to_py_runtime_error)?;
        serialize_to_python(py, &result)
    }

    /// Evaluate an input and return the runtime result payload directly.
    ///
    /// For gate and action artifacts this is the same schema-shaped payload
    /// returned by `logicpearl run --json`. For pipelines this returns the
    /// pipeline execution payload.
    fn evaluate(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let input = py_any_to_json(input)?;
        let result = py
            .allow_threads(|| self.inner.run_json_value(&input))
            .map_err(to_py_runtime_error)?;
        let value = runtime_result_value(result).map_err(to_py_runtime_error)?;
        serialize_to_python(py, &value)
    }

    /// Evaluate one input and return the runtime result payload directly.
    fn evaluate_single(&self, py: Python<'_>, input: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let input = py_any_to_json(input)?;
        let result = py
            .allow_threads(|| self.inner.run_single_json(&input))
            .map_err(to_py_runtime_error)?;
        let value = single_runtime_result_value(result).map_err(to_py_runtime_error)?;
        serialize_to_python(py, &value)
    }

    /// Evaluate a list of inputs and return a list of runtime result payloads.
    fn evaluate_batch(&self, py: Python<'_>, inputs: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let value = py_any_to_json(inputs)?;
        let items = value.as_array().ok_or_else(|| {
            PyValueError::new_err("evaluate_batch expects a JSON-compatible Python list")
        })?;
        let result = py
            .allow_threads(|| self.inner.run_batch_json(items))
            .map_err(to_py_runtime_error)?;
        let value = batch_runtime_result_value(result).map_err(to_py_runtime_error)?;
        serialize_to_python(py, &value)
    }
}

#[pyfunction]
fn load_engine(path: &str) -> PyResult<PyLogicPearlEngine> {
    Ok(PyLogicPearlEngine {
        inner: LogicPearlEngine::from_path(path).map_err(to_py_runtime_error)?,
    })
}

#[pymodule]
fn _logicpearl(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add_class::<PyLogicPearlEngine>()?;
    module.add_function(wrap_pyfunction!(load_engine, module)?)?;

    let doc = "Python bindings for logicpearl-engine.";
    module.add("__doc__", doc)?;
    let _ = py;
    Ok(())
}

fn runtime_result_value(envelope: EngineExecutionEnvelope) -> Result<Value, LogicPearlError> {
    match envelope {
        EngineExecutionEnvelope::Single(execution) => single_runtime_result_value(*execution),
        EngineExecutionEnvelope::Batch(execution) => batch_runtime_result_value(execution),
    }
}

fn single_runtime_result_value(execution: EngineSingleExecution) -> Result<Value, LogicPearlError> {
    let value = match execution {
        EngineSingleExecution::Artifact(output) => serde_json::to_value(output.evaluation),
        EngineSingleExecution::ActionArtifact(output) => serde_json::to_value(output.evaluation),
        EngineSingleExecution::Pipeline(output) => serde_json::to_value(output),
        EngineSingleExecution::Fanout(output) => serde_json::to_value(output),
    }?;
    Ok(value)
}

fn batch_runtime_result_value(execution: EngineBatchExecution) -> Result<Value, LogicPearlError> {
    let value = match execution {
        EngineBatchExecution::Artifact(output) => serde_json::to_value(output.evaluations),
        EngineBatchExecution::ActionArtifact(output) => serde_json::to_value(output.evaluations),
        EngineBatchExecution::Pipeline(output) => serde_json::to_value(output),
        EngineBatchExecution::Fanout(output) => serde_json::to_value(output),
    }?;
    Ok(value)
}

fn py_any_to_json(value: &Bound<'_, PyAny>) -> PyResult<Value> {
    if value.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(raw) = value.downcast::<PyBool>() {
        return Ok(Value::Bool(raw.is_true()));
    }
    if let Ok(raw) = value.downcast::<PyInt>() {
        if let Ok(number) = raw.extract::<i64>() {
            return Ok(Value::Number(Number::from(number)));
        }
        if let Ok(number) = raw.extract::<u64>() {
            return Ok(Value::Number(Number::from(number)));
        }
        return Err(PyValueError::new_err(
            "JSON integers must fit in signed or unsigned 64-bit range",
        ));
    }
    if let Ok(raw) = value.downcast::<PyFloat>() {
        let number = raw.extract::<f64>()?;
        let number = Number::from_f64(number)
            .ok_or_else(|| PyValueError::new_err("JSON numbers must be finite"))?;
        return Ok(Value::Number(number));
    }
    if let Ok(raw) = value.downcast::<PyString>() {
        return Ok(Value::String(raw.extract::<String>()?));
    }
    if let Ok(raw) = value.downcast::<PyList>() {
        let mut output = Vec::with_capacity(raw.len());
        for item in raw.iter() {
            output.push(py_any_to_json(&item)?);
        }
        return Ok(Value::Array(output));
    }
    if let Ok(raw) = value.downcast::<PyTuple>() {
        let mut output = Vec::with_capacity(raw.len());
        for item in raw.iter() {
            output.push(py_any_to_json(&item)?);
        }
        return Ok(Value::Array(output));
    }
    if let Ok(raw) = value.downcast::<PyDict>() {
        let mut output = Map::new();
        for (key, item) in raw.iter() {
            let key = key.extract::<String>().map_err(|_| {
                PyValueError::new_err("JSON object keys must be strings for LogicPearl input")
            })?;
            output.insert(key, py_any_to_json(&item)?);
        }
        return Ok(Value::Object(output));
    }

    Err(PyValueError::new_err(
        "input must be JSON-compatible: dict, list, tuple, str, int, float, bool, or None",
    ))
}

fn serialize_to_python(py: Python<'_>, value: &impl Serialize) -> PyResult<Py<PyAny>> {
    let json = PyModule::import(py, "json")?;
    let text = serde_json::to_string(value).map_err(|err| {
        PyRuntimeError::new_err(format!("failed to serialize LogicPearl result: {err}"))
    })?;
    Ok(json.getattr("loads")?.call1((text,))?.unbind())
}

fn to_py_runtime_error(err: LogicPearlError) -> PyErr {
    PyRuntimeError::new_err(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyDict;
    use serde_json::json;
    use std::path::{Path, PathBuf};

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|path| path.parent())
            .expect("package should live under logicpearl/packages/logicpearl-python")
            .to_path_buf()
    }

    #[test]
    fn wrapper_reports_pipeline_kind() {
        let pipeline =
            repo_root().join("examples/pipelines/observer_membership_verify/pipeline.json");
        let engine = PyLogicPearlEngine {
            inner: LogicPearlEngine::from_path(&pipeline).expect("pipeline should load"),
        };
        assert_eq!(engine.kind(), "pipeline");
        assert!(engine.source_path().ends_with("pipeline.json"));
    }

    #[test]
    fn converts_python_input_to_json_value() {
        Python::with_gil(|py| {
            let payload = PyDict::new(py);
            payload
                .set_item("member", true)
                .expect("python dict should accept bool");
            payload
                .set_item("age", 34)
                .expect("python dict should accept integer");
            payload
                .set_item("country", "US")
                .expect("python dict should accept string");

            let value = py_any_to_json(payload.as_any()).expect("python payload should convert");
            assert_eq!(
                value,
                json!({
                    "member": true,
                    "age": 34,
                    "country": "US"
                })
            );
        });
    }

    #[test]
    fn evaluate_returns_runtime_result_payload() {
        Python::with_gil(|py| {
            let artifact = repo_root().join("fixtures/ir/valid/auth-demo-v1.json");
            let engine = PyLogicPearlEngine {
                inner: LogicPearlEngine::from_artifact_path(&artifact).expect("artifact loads"),
            };
            let payload = PyDict::new(py);
            payload
                .set_item("action", "delete")
                .expect("python dict should accept string");
            payload
                .set_item("resource_archived", true)
                .expect("python dict should accept bool");
            payload
                .set_item("user_role", "viewer")
                .expect("python dict should accept string");
            payload
                .set_item("failed_attempts", 99)
                .expect("python dict should accept integer");

            let result = engine
                .evaluate(py, payload.as_any())
                .expect("artifact should evaluate");
            let result = result.bind(py);
            let result = result
                .downcast::<PyDict>()
                .expect("runtime result should be a Python dict");
            let decision_kind = result
                .get_item("decision_kind")
                .expect("dict lookup should succeed")
                .expect("runtime result should include decision_kind")
                .extract::<String>()
                .expect("decision_kind should be a string");
            let allow = result
                .get_item("allow")
                .expect("dict lookup should succeed")
                .expect("runtime result should include allow")
                .extract::<bool>()
                .expect("allow should be a bool");

            assert_eq!(decision_kind, "gate");
            assert!(!allow);
        });
    }
}
